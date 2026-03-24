cmake_minimum_required(VERSION 3.10)
project(wychcheck C)

set(WOLFSSL_DIR "$ENV{WOLFSSL_DIR}")

if(NOT WOLFSSL_DIR)
    message(FATAL_ERROR "Set WOLFSSL_DIR to a built wolfssl source tree")
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

add_executable(wychcheck
    src/main.c
    src/hex.c
    src/cjson/cJSON.c
    src/runners/aead.c
    src/runners/mac.c
    src/runners/hkdf.c
    src/runners/ind_cpa.c
    src/runners/keywrap.c
    src/runners/ecdh.c
    src/runners/ecdsa.c
    src/runners/ecdsa_p1363.c
    src/runners/eddsa.c
    src/runners/xdh.c
    src/runners/rsa_sig.c
    src/runners/rsa_oaep.c
    src/runners/rsa_pss.c
)

target_include_directories(wychcheck PRIVATE src)
target_compile_definitions(wychcheck PRIVATE
    WYCHEPROOF_DEFAULT="${CMAKE_CURRENT_SOURCE_DIR}/wycheproof"
)
target_link_libraries(wychcheck ${WOLFSSL_LIB} m pthread)

# Force RPATH (not RUNPATH) so the binary finds the correct libwolfssl.so
# even when a different version is installed system-wide in ldconfig.
# RUNPATH is searched after ldconfig; RPATH is searched before it.
get_filename_component(WOLFSSL_LIB_DIR ${WOLFSSL_LIB} DIRECTORY)
set_target_properties(wychcheck PROPERTIES
    BUILD_RPATH "${WOLFSSL_LIB_DIR}"
    INSTALL_RPATH "${WOLFSSL_LIB_DIR}"
)
target_link_options(wychcheck PRIVATE "LINKER:--disable-new-dtags")
