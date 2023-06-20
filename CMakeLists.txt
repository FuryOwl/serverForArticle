cmake_minimum_required(VERSION 3.2)
project(base64server)

set(CMAKE_CXX_STANDARD 14)

set(SOURCES main.cpp sqlite3.c)

if(WIN32)
    set(SYSTEM_LIBRARIES ws2_32)
else()
    set(SYSTEM_LIBRARIES)
endif()

add_executable(base64server ${SOURCES})

target_include_directories(base64server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(base64server ${SYSTEM_LIBRARIES})
