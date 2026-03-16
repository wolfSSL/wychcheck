cmake_minimum_required(VERSION 3.10)
project(wychcheck C)

set(WOLFSSL_DIR "$ENV{WOLFSSL_DIR}")
set(WYCHEPROOF_DIR "$ENV{WYCHEPROOF_DIR}")

if(NOT WOLFSSL_DIR)
    message(FATAL_ERROR "Set WOLFSSL_DIR to a built wolfssl source tree")
endif()
if(NOT WYCHEPROOF_DIR)
    message(FATAL_ERROR "Set WYCHEPROOF_DIR to a wycheproof repo checkout")
endif()

# wolfssl headers live at WOLFSSL_DIR root (for #include <wolfssl/options.h>)
include_directories(${WOLFSSL_DIR})

# autotools build: libwolfssl in src/.libs/
# cmake build: libwolfssl in build dir or lib/
find_library(WOLFSSL_LIB wolfssl
    PATHS
        ${WOLFSSL_DIR}/src/.libs
        ${WOLFSSL_DIR}/lib
        ${WOLFSSL_DIR}/build
    NO_DEFAULT_PATH
)
if(NOT WOLFSSL_LIB)
    message(FATAL_ERROR "Cannot find libwolfssl in ${WOLFSSL_DIR}")
endif()
message(STATUS "Using wolfssl: ${WOLFSSL_LIB}")

file(GLOB RUNNER_SRCS src/runners/*.c)

add_executable(wychcheck
    src/main.c
    src/hex.c
    src/cjson/cJSON.c
    ${RUNNER_SRCS}
)

target_include_directories(wychcheck PRIVATE src)
target_link_libraries(wychcheck ${WOLFSSL_LIB} m pthread)

# so the binary finds libwolfssl.so at runtime even if a system copy exists
get_filename_component(WOLFSSL_LIB_DIR ${WOLFSSL_LIB} DIRECTORY)
set_target_properties(wychcheck PROPERTIES
    BUILD_RPATH "${WOLFSSL_LIB_DIR}"
    INSTALL_RPATH "${WOLFSSL_LIB_DIR}"
)
# prefer our RPATH over system paths
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
