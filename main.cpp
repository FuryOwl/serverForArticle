#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <bitset>
#include <queue>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#define SOCKET int
#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKET_ERROR -1
#endif

const unsigned short SERVER_PORT = 8080;
const int MAX_CONNECTIONS = 10;
static const std::string base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64ToString(const std::string& base64_string) {
    // Finding the number of occurrences of the '=' character to skip it
    int counter = std::count(base64_string.begin(), base64_string.end(), '=');
    // Converting a base64 string to a bit sequence
    std::string bit_string;
    std::bitset<6> binary_number;
    for (size_t i = 0; i < base64_string.size() - counter; i++) {
        binary_number = std::bitset<6>(base64_alphabet.find(base64_string[i]));
        bit_string += binary_number.to_string();
    }
    // Removing extra zero bits
    if (counter == 2) {
        bit_string.resize(bit_string.size() - 4);
    }
    else if (counter == 1) {
        bit_string.resize(bit_string.size() - 2);
    }
    // Converting a bit sequence to a regular string
    std::string decoded_string;
    std::bitset<8> binary_char;
    for (size_t i = 0; i < bit_string.size(); i += 8) {
        binary_char = std::bitset<8>(bit_string.substr(i, 8));
        decoded_string += static_cast<char>(binary_char.to_ulong());
    }

    return decoded_string;
}

void ClientHandler(SOCKET clientSocket, sockaddr_in clientAddress) {
    // Get the client IP address and port
    char clientIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIp, INET_ADDRSTRLEN);
    unsigned short clientPort = ntohs(clientAddress.sin_port);

    std::cout << "Client connected from IP: " << clientIp << ", Port: " << clientPort << std::endl;

    // Handle client data
    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead <= 0) {
        std::cerr << "Failed to read data from client" << std::endl;
#ifdef _WIN32
        closesocket(clientSocket);
#else
        close(clientSocket);
#endif
        return;
    }

    // Null-terminate the received data
    buffer[bytesRead] = '\0';

    // Decode the received text from Base64
    std::string received_text = Base64ToString(buffer);

    // Display the received and decoded text
    std::cout << "Received: '" << buffer << "' Decoded: '" << received_text << "'" << std::endl;

#ifdef _WIN32
    closesocket(clientSocket);
#else
    close(clientSocket);
#endif
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }
#endif

    // Create a socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // Bind the socket to the server address
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddress.sin_port = htons(SERVER_PORT); // Change the port number if needed

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Failed to bind socket to the server address" << std::endl;
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return 1;
    }

    // Get the IP address and port
    char ipAddress[16];
    inet_ntop(AF_INET, &(serverAddress.sin_addr), ipAddress, sizeof(ipAddress));
    unsigned short port = ntohs(serverAddress.sin_port);

    std::cout << "Server is listening on IP: " << ipAddress << ", Port: " << port << std::endl;

    // Listen for incoming connections
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Failed to listen for connections" << std::endl;
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return 1;
    }

    std::mutex mutex;
    std::queue<SOCKET> clientQueue;

    // Accept and handle client connections
    while (true) {
        sockaddr_in clientAddress{};
        socklen_t clientAddressSize = sizeof(clientAddress);

        SOCKET clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddress), &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to accept client connection" << std::endl;
#ifdef _WIN32
            closesocket(serverSocket);
            WSACleanup();
#else
            close(serverSocket);
#endif
            return 1;
        }

        {
            std::lock_guard<std::mutex> lock(mutex);
            if (clientQueue.size() < MAX_CONNECTIONS) {
                clientQueue.push(clientSocket);
            }
            else {
                std::cerr << "Maximum number of clients reached. Rejecting new connection." << std::endl;
#ifdef _WIN32
                closesocket(clientSocket);
#else
                close(clientSocket);
#endif
                continue;
            }
        }

        std::thread clientThread(ClientHandler, clientSocket, clientAddress);
        clientThread.detach();
    }

#ifdef _WIN32
    closesocket(serverSocket);
    WSACleanup();
#else
    close(serverSocket);
#endif

    return 0;
}
