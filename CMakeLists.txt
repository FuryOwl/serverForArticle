cmake_minimum_required(VERSION 3.2)
project(ServerForBase64)

set(CMAKE_CXX_STANDARD 14)

set(SOURCES main.cpp)

if(WIN32)
    set(SYSTEM_LIBRARIES ws2_32)
else()
    set(SYSTEM_LIBRARIES)
endif()

add_executable(ServerForBase64 ${SOURCES})

target_link_libraries(ServerForBase64 ${SYSTEM_LIBRARIES})
