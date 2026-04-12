cmake_minimum_required(VERSION 3.10)
project(wolfcrypt-check C)

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

add_executable(wolfcrypt-check
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
    src/runners/mldsa.c
    src/runners/mldsa_acvp.c
    src/runners/mlkem.c
    src/runners/pbkdf2.c
    src/runners/pbes2.c
)

target_include_directories(wolfcrypt-check PRIVATE src)
target_compile_definitions(wolfcrypt-check PRIVATE
    WYCHEPROOF_DEFAULT="${CMAKE_CURRENT_SOURCE_DIR}/wycheproof"
    ACVP_DEFAULT="${CMAKE_CURRENT_SOURCE_DIR}/testvectors_acvp"
)
target_link_libraries(wolfcrypt-check ${WOLFSSL_LIB} m pthread)

# Force RPATH (not RUNPATH) so the binary finds the correct libwolfssl.so
# even when a different version is installed system-wide in ldconfig.
# RUNPATH is searched after ldconfig; RPATH is searched before it.
get_filename_component(WOLFSSL_LIB_DIR ${WOLFSSL_LIB} DIRECTORY)
set_target_properties(wolfcrypt-check PROPERTIES
    BUILD_RPATH "${WOLFSSL_LIB_DIR}"
    INSTALL_RPATH "${WOLFSSL_LIB_DIR}"
)
target_link_options(wolfcrypt-check PRIVATE "LINKER:--disable-new-dtags")
