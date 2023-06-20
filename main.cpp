#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <bitset>
#include <queue>
#include <algorithm>
#include "sqlite3.h"

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

int InsertRawData(sqlite3* db, const std::string& data) {
    const char* query = "INSERT INTO RAW (data) VALUES (?);";

    sqlite3_stmt* statement;
    if (sqlite3_prepare_v2(db, query, -1, &statement, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare RAW insert statement: " << sqlite3_errmsg(db) << std::endl;
        return SQLITE_ERROR;
    }

    if (sqlite3_bind_text(statement, 1, data.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        std::cerr << "Failed to bind value to RAW insert statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(statement);
        return SQLITE_ERROR;
    }

    int result = sqlite3_step(statement);
    if (result != SQLITE_DONE) {
        std::cerr << "Failed to execute RAW insert statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(statement);
        return result;
    }

    sqlite3_finalize(statement);
    return SQLITE_OK;
}

int InsertBase64Data(sqlite3* db, const std::string& base64Data) {
    const char* query = "INSERT INTO BASE64 (base64_data) VALUES (?);";

    sqlite3_stmt* statement;
    if (sqlite3_prepare_v2(db, query, -1, &statement, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare BASE64 insert statement: " << sqlite3_errmsg(db) << std::endl;
        return SQLITE_ERROR;
    }

    if (sqlite3_bind_text(statement, 1, base64Data.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        std::cerr << "Failed to bind base64_data to BASE64 insert statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(statement);
        return SQLITE_ERROR;
    }

    int result = sqlite3_step(statement);
    if (result != SQLITE_DONE) {
        std::cerr << "Failed to execute BASE64 insert statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(statement);
        return result;
    }

    sqlite3_finalize(statement);
    return SQLITE_OK;
}

void ClientHandler(SOCKET clientSocket, sockaddr_in clientAddress, sqlite3* db) {
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

    // Insert data into database
    int result = InsertRawData(db, received_text);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to insert data into RAW table: " << result << std::endl;
    }

    result = InsertBase64Data(db, buffer);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to insert data into BASE64 table: " << result << std::endl;
    }

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
        std::cerr << "Failed to initialize winsock" << std::endl;
        return EXIT_FAILURE;
    }
#endif

    // Create a socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    // Bind the socket to an address and port
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(SERVER_PORT);
    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Failed to bind socket" << std::endl;
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return EXIT_FAILURE;
    }

    // Start listening for incoming connections
    if (listen(serverSocket, MAX_CONNECTIONS) == SOCKET_ERROR) {
        std::cerr << "Failed to listen on socket" << std::endl;
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return EXIT_FAILURE;
    }

    std::cout << "Server started. Listening on port " << SERVER_PORT << std::endl;

    // Open the database connection
    sqlite3* db;
    if (sqlite3_open("database.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open database connection" << std::endl;
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return EXIT_FAILURE;
    }

    // Check if the RAW table already exists
    int tableExists = 0;
    const char* tableExistsQuery = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='RAW';";
    sqlite3_stmt* tableExistsStmt;
    if (sqlite3_prepare_v2(db, tableExistsQuery, -1, &tableExistsStmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(tableExistsStmt) == SQLITE_ROW) {
            tableExists = sqlite3_column_int(tableExistsStmt, 0);
        }
        sqlite3_finalize(tableExistsStmt);
    }

    if (!tableExists) {
        // Prepare the RAW table creation statement
        sqlite3_stmt* rawTableStmt;
        const char* rawTableQuery = "CREATE TABLE RAW (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);";
        if (sqlite3_prepare_v2(db, rawTableQuery, -1, &rawTableStmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare RAW table creation statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
#ifdef _WIN32
            closesocket(serverSocket);
            WSACleanup();
#else
            close(serverSocket);
#endif
            return EXIT_FAILURE;
        }

        // Execute the RAW table creation statement
        if (sqlite3_step(rawTableStmt) != SQLITE_DONE) {
            std::cerr << "Failed to create RAW table: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(rawTableStmt);
            sqlite3_close(db);
#ifdef _WIN32
            closesocket(serverSocket);
            WSACleanup();
#else
            close(serverSocket);
#endif
            return EXIT_FAILURE;
        }

        // Finalize the RAW table statement
        sqlite3_finalize(rawTableStmt);
    }

    // Check if the BASE64 table already exists
    int base64TableExists = 0;
    const char* base64TableExistsQuery = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='BASE64';";
    sqlite3_stmt* base64TableExistsStmt;
    if (sqlite3_prepare_v2(db, base64TableExistsQuery, -1, &base64TableExistsStmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(base64TableExistsStmt) == SQLITE_ROW) {
            base64TableExists = sqlite3_column_int(base64TableExistsStmt, 0);
        }
        sqlite3_finalize(base64TableExistsStmt);
    }

    if (!base64TableExists) {
        // Prepare the BASE64 table creation statement
        sqlite3_stmt* base64TableStmt;
        const char* base64TableQuery = "CREATE TABLE BASE64 (id INTEGER PRIMARY KEY AUTOINCREMENT, base64_data TEXT NOT NULL)";
        if (sqlite3_prepare_v2(db, base64TableQuery, -1, &base64TableStmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare BASE64 table creation statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
#ifdef _WIN32
            closesocket(serverSocket);
            WSACleanup();
#else
            close(serverSocket);
#endif
            return EXIT_FAILURE;
        }

        // Execute the BASE64 table creation statement
        if (sqlite3_step(base64TableStmt) != SQLITE_DONE) {
            std::cerr << "Failed to create BASE64 table: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(base64TableStmt);
            sqlite3_close(db);
#ifdef _WIN32
            closesocket(serverSocket);
            WSACleanup();
#else
            close(serverSocket);
#endif
            return EXIT_FAILURE;
        }

        // Finalize the BASE64 table statement
        sqlite3_finalize(base64TableStmt);
    }

    // Accept and handle incoming connections
    while (true) {
        sockaddr_in clientAddress{};
        socklen_t clientAddressSize = sizeof(clientAddress);

        SOCKET clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddress), &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to accept client connection" << std::endl;
            break;
        }

        std::thread clientThread(ClientHandler, clientSocket, clientAddress, db);
        clientThread.detach();
    }

    // Close the database connection
    sqlite3_close(db);

    // Close the server socket
#ifdef _WIN32
    closesocket(serverSocket);
    WSACleanup();
#else
    close(serverSocket);
#endif

    return EXIT_SUCCESS;
}
