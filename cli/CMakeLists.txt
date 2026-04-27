cmake_minimum_required(VERSION 3.16)

# Produce a fully static `blin` binary. Intended for musl-based builds
# (Alpine + libsodium-static + mbedtls-static) so the artifact runs on any
# Linux distribution without library version skew.
option(BLIN_STATIC "Statically link the blin binary" OFF)

# When asked for a static build, make `find_library` prefer .a over .so.
# Without this, find_library returns the full path to libmbedtls.so and
# the eventual `-static` flag has no effect because full-path arguments
# bypass the linker's static/dynamic search rules.
if(BLIN_STATIC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

# --- libsodium: prefer vcpkg's CMake config, fall back to pkg-config (Linux). --
find_package(unofficial-sodium CONFIG QUIET)
if(unofficial-sodium_FOUND)
    set(BLIN_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(BLIN_SODIUM_TARGET PkgConfig::SODIUM)
endif()

# --- mbedTLS: prefer vcpkg's CMake config, fall back to find_library. ---------
find_package(MbedTLS CONFIG QUIET)
if(MbedTLS_FOUND)
    set(BLIN_MBEDTLS_TARGETS MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
    set(BLIN_MBEDTLS_INCLUDE "")
else()
    find_library(MBEDTLS_LIB    mbedtls    REQUIRED)
    find_library(MBEDX509_LIB   mbedx509   REQUIRED)
    find_library(MBEDCRYPTO_LIB mbedcrypto REQUIRED)
    find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h REQUIRED)
    set(BLIN_MBEDTLS_TARGETS ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB})
    set(BLIN_MBEDTLS_INCLUDE ${MBEDTLS_INCLUDE_DIR})
endif()

add_executable(blin
    main.cpp
    config.cpp
    http.cpp
    crypto.cpp
    payload.cpp
    url.cpp
    pow_solve.cpp
    ../src/util.cpp
    ../src/sha256/sha256.cpp
)

target_include_directories(blin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${BLIN_MBEDTLS_INCLUDE}
)

target_link_libraries(blin PRIVATE
    ${BLIN_SODIUM_TARGET}
    ${BLIN_MBEDTLS_TARGETS}
)

if(WIN32)
    # ws2_32 — sockets via mbedtls_net_*; crypt32 — Windows cert store
    # (CertOpenSystemStore/CertEnumCertificatesInStore) used as the source
    # of trusted CA roots for HTTPS verification.
    target_link_libraries(blin PRIVATE ws2_32 crypt32)
else()
    target_link_libraries(blin PRIVATE pthread)
endif()

if(BLIN_STATIC)
    target_link_options(blin PRIVATE -static)
    set_target_properties(blin PROPERTIES
        LINK_SEARCH_START_STATIC ON
        LINK_SEARCH_END_STATIC   ON)
endif()

include(GNUInstallDirs)
install(TARGETS blin RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
