cmake_minimum_required(VERSION 3.16)

# APP_VERSION is computed in the root CMakeLists. We just resolve a short
# git hash here for embedding into the version banner.
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_SHORT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT GIT_SHORT_HASH)
    set(GIT_SHORT_HASH "unknown")
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/version.h
    @ONLY
)
configure_file(
    ${CMAKE_SOURCE_DIR}/web/src/version.js.in
    ${CMAKE_SOURCE_DIR}/web/src/version.js
    @ONLY
)

find_package(SQLite3 REQUIRED)

add_executable(cryptoblin
    main.cpp
    config.cpp
    db.cpp
    pow.cpp
    util.cpp
    webapi.cpp
    config/inireader.cpp
    config/ini_backend/ini.c
    sha256/sha256.cpp
)

target_include_directories(cryptoblin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(cryptoblin PRIVATE
    SQLite::SQLite3
    pthread
)

include(GNUInstallDirs)
install(TARGETS cryptoblin RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
