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

# Under BLIN_STATIC we deliberately avoid CMake CONFIG packages (vcpkg's
# `unofficial-sodium`, Alpine's `MbedTLS`) — their imported targets pin the
# full path to a `.so` in INTERFACE_LINK_LIBRARIES, which silently bypasses
# CMAKE_FIND_LIBRARY_SUFFIXES and the eventual `-static` linker flag, and
# we end up dynamically linked anyway. With BLIN_STATIC we go straight to
# find_library and let the suffix override pick `.a`.

# --- libsodium ----------------------------------------------------------------
if(NOT BLIN_STATIC)
    find_package(unofficial-sodium CONFIG QUIET)
endif()
if(unofficial-sodium_FOUND)
    set(BLIN_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_library(SODIUM_LIB sodium REQUIRED)
    find_path(SODIUM_INCLUDE_DIR sodium.h REQUIRED)
    set(BLIN_SODIUM_TARGET ${SODIUM_LIB})
    set(BLIN_SODIUM_INCLUDE ${SODIUM_INCLUDE_DIR})
endif()

# --- mbedTLS ------------------------------------------------------------------
if(NOT BLIN_STATIC)
    find_package(MbedTLS CONFIG QUIET)
endif()
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
    ${BLIN_SODIUM_INCLUDE}
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
