cmake_minimum_required(VERSION 3.16)
project(cryptoblin LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Project version. CI passes APP_VERSION via env; otherwise we ask git. ----
if(DEFINED ENV{APP_VERSION})
    string(REGEX REPLACE "^v" "" APP_VERSION "$ENV{APP_VERSION}")
else()
    execute_process(
        COMMAND git describe --tags --dirty
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE _GIT_DESC
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(_GIT_DESC)
        string(REGEX REPLACE "^v" "" APP_VERSION "${_GIT_DESC}")
    else()
        set(APP_VERSION "dev")
    endif()
endif()
message(STATUS "cryptoblin version: ${APP_VERSION}")

option(BUILD_SERVER "Build the cryptoblin HTTP server" ON)
option(BUILD_CLI    "Build the blin CLI client"        ON)

if(BUILD_SERVER)
    add_subdirectory(src)
    add_subdirectory(packaging)
endif()
if(BUILD_CLI)
    add_subdirectory(cli)
endif()

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# --- Debian package metadata. Only meaningful when the server is in the build
#     (`BUILD_SERVER=ON`). Run with `cd build && cpack -G DEB`.
if(BUILD_SERVER)
    string(REGEX REPLACE "[^0-9A-Za-z.+~-]" "~" CPACK_PACKAGE_VERSION "${APP_VERSION}")
    set(CPACK_PACKAGE_NAME "cryptoblin")
    set(CPACK_PACKAGE_VENDOR "askhatovich")
    set(CPACK_PACKAGE_CONTACT "Roman <167345407+askhatovich@users.noreply.github.com>")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
        "Self-hosted zero-knowledge note and file sharing")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/askhatovich/cryptoblin")

    set(CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_SECTION "web")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    # Resolve runtime library dependencies from the actual binary.
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

    set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
    include(CPack)
endif()
