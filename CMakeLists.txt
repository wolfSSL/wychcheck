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
    src/runners/dsa.c
    src/runners/rsa_sig.c
    src/runners/rsa_decrypt.c
    src/runners/rsa_oaep.c
    src/runners/rsa_pss.c
    src/runners/mldsa.c
    src/runners/mldsa_acvp.c
    src/runners/mlkem.c
    src/runners/mlkem_acvp.c
    src/runners/pbkdf2.c
    src/runners/pbes2.c
    src/runners/slhdsa_acvp.c
    src/runners/daead.c
    src/runners/mac_with_iv.c
    src/runners/rsa_sign.c
)

target_include_directories(wolfcrypt-check PRIVATE src)
target_compile_definitions(wolfcrypt-check PRIVATE
    WYCHEPROOF_DEFAULT="${CMAKE_CURRENT_SOURCE_DIR}/wycheproof"
    ACVP_DEFAULT="${CMAKE_CURRENT_SOURCE_DIR}/testvectors_acvp"
    RFC_DEFAULT="${CMAKE_CURRENT_SOURCE_DIR}/testvectors_rfc"
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

# CTest integration — the RPATH baked above means no LD_LIBRARY_PATH is needed.
# WYCHEPROOF_DEFAULT / ACVP_DEFAULT / RFC_DEFAULT are compiled-in absolute paths,
# so no extra environment variables are required either.
enable_testing()
add_test(NAME wycheproof COMMAND wolfcrypt-check)

# Per-algorithm CTest targets — one entry per algorithm family.
# --filter=<substr>  : run only files whose name contains the substring.
# --filter=^<prefix> : run only files whose name starts with the prefix.
# Use: ctest -R <name>  or  ctest -L <label>

# AEAD
add_test(NAME wycheproof/aes-gcm            COMMAND wolfcrypt-check --filter=aes_gcm_test)
add_test(NAME wycheproof/aes-ccm            COMMAND wolfcrypt-check --filter=aes_ccm_test)
add_test(NAME wycheproof/aes-eax            COMMAND wolfcrypt-check --filter=aes_eax_test)
add_test(NAME wycheproof/aes-siv-aead       COMMAND wolfcrypt-check --filter=aead_aes_siv_cmac)
add_test(NAME wycheproof/aes-siv-daead      COMMAND wolfcrypt-check --filter=aes_siv_cmac_test)
add_test(NAME wycheproof/aes-gmac           COMMAND wolfcrypt-check --filter=aes_gmac_test)
add_test(NAME wycheproof/chacha20-poly1305  COMMAND wolfcrypt-check --filter=^chacha20_poly1305_test)
add_test(NAME wycheproof/xchacha20-poly1305 COMMAND wolfcrypt-check --filter=xchacha20_poly1305_test)
set_tests_properties(
    wycheproof/aes-gcm wycheproof/aes-ccm wycheproof/aes-eax
    wycheproof/aes-siv-aead wycheproof/aes-siv-daead wycheproof/aes-gmac
    wycheproof/chacha20-poly1305 wycheproof/xchacha20-poly1305
    PROPERTIES LABELS "aead")

# MAC
add_test(NAME wycheproof/hmac     COMMAND wolfcrypt-check --filter=hmac_sha)
add_test(NAME wycheproof/siphash  COMMAND wolfcrypt-check --filter=siphash_)
add_test(NAME wycheproof/aes-cmac COMMAND wolfcrypt-check --filter=aes_cmac_test)
set_tests_properties(
    wycheproof/hmac wycheproof/siphash wycheproof/aes-cmac
    PROPERTIES LABELS "mac")

# Symmetric ciphers
add_test(NAME wycheproof/aes-cbc COMMAND wolfcrypt-check --filter=aes_cbc_pkcs5_test)
add_test(NAME wycheproof/aes-xts COMMAND wolfcrypt-check --filter=aes_xts_test)
add_test(NAME wycheproof/aes-kw  COMMAND wolfcrypt-check --filter=aes_wrap_test)
add_test(NAME wycheproof/aes-kwp COMMAND wolfcrypt-check --filter=aes_kwp_test)
set_tests_properties(
    wycheproof/aes-cbc wycheproof/aes-xts
    wycheproof/aes-kw wycheproof/aes-kwp
    PROPERTIES LABELS "symmetric")

# KDF
add_test(NAME wycheproof/hkdf   COMMAND wolfcrypt-check --filter=hkdf_sha)
add_test(NAME wycheproof/pbkdf2 COMMAND wolfcrypt-check --filter=pbkdf2_hmac)
add_test(NAME wycheproof/pbes2  COMMAND wolfcrypt-check --filter=pbes2_hmac)
set_tests_properties(
    wycheproof/hkdf wycheproof/pbkdf2 wycheproof/pbes2
    PROPERTIES LABELS "kdf")

# ECDH and XDH
add_test(NAME wycheproof/ecdh   COMMAND wolfcrypt-check --filter=^ecdh_)
add_test(NAME wycheproof/x25519 COMMAND wolfcrypt-check --filter=x25519)
add_test(NAME wycheproof/x448   COMMAND wolfcrypt-check --filter=x448)
set_tests_properties(
    wycheproof/ecdh wycheproof/x25519 wycheproof/x448
    PROPERTIES LABELS "ecdh")

# Digital signatures
add_test(NAME wycheproof/ecdsa         COMMAND wolfcrypt-check --filter=^ecdsa_)
add_test(NAME wycheproof/eddsa         COMMAND wolfcrypt-check --filter=^ed)
add_test(NAME wycheproof/dsa           COMMAND wolfcrypt-check --filter=^dsa_)
add_test(NAME wycheproof/rsa-pkcs1     COMMAND wolfcrypt-check --filter=rsa_pkcs1)
add_test(NAME wycheproof/rsa-signature COMMAND wolfcrypt-check --filter=rsa_signature)
add_test(NAME wycheproof/rsa-oaep      COMMAND wolfcrypt-check --filter=oaep)
add_test(NAME wycheproof/rsa-pss       COMMAND wolfcrypt-check --filter=rsa_pss)
set_tests_properties(
    wycheproof/ecdsa wycheproof/eddsa wycheproof/dsa
    wycheproof/rsa-pkcs1 wycheproof/rsa-signature
    wycheproof/rsa-oaep wycheproof/rsa-pss
    PROPERTIES LABELS "signature")

# Post-quantum
add_test(NAME wycheproof/mldsa  COMMAND wolfcrypt-check --filter=mldsa)
add_test(NAME wycheproof/mlkem  COMMAND wolfcrypt-check --filter=mlkem)
add_test(NAME wycheproof/slhdsa COMMAND wolfcrypt-check --filter=slhdsa)
set_tests_properties(
    wycheproof/mldsa wycheproof/mlkem wycheproof/slhdsa
    PROPERTIES LABELS "pqc")

# RFC reference vectors
add_test(NAME wycheproof/rfc COMMAND wolfcrypt-check --filter=^rfc)
set_tests_properties(wycheproof/rfc PROPERTIES LABELS "rfc")
