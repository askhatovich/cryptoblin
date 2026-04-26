cmake_minimum_required(VERSION 3.16)
project(cryptoblin LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_SERVER "Build the cryptoblin HTTP server" ON)
option(BUILD_CLI    "Build the blin CLI client"        ON)

if(BUILD_SERVER)
    add_subdirectory(src)
endif()
if(BUILD_CLI)
    add_subdirectory(cli)
endif()

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
