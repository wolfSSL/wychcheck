# wychcheck

Test [wolfSSL](https://www.wolfssl.com/) wolfcrypt against [Project Wycheproof](https://github.com/google/wycheproof) test vectors.

wychcheck is a standalone C project that links against a built wolfSSL library and runs Wycheproof's cryptographic test vectors against wolfcrypt APIs. It automatically adapts to wolfSSL's compile-time feature flags (`wolfssl/options.h`), skipping tests for features that aren't compiled in.

## Supported algorithms

Covers 13 Wycheproof test schemas:

- **AEAD** -- AES-GCM, AES-CCM, AES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305
- **MAC** -- HMAC, AES-CMAC, SipHash
- **HKDF**
- **IND-CPA** -- AES-CBC, AES-XTS
- **Key Wrap** -- AES-KW
- **ECDH**
- **ECDSA** -- DER and P1363 signature formats
- **EdDSA** -- Ed25519, Ed448
- **XDH** -- X25519, X448
- **RSA PKCS#1 v1.5** -- signature verification
- **RSA-OAEP** -- decryption
- **RSA-PSS** -- signature verification

## Prerequisites

- A C compiler and CMake (>= 3.10)
- A **built** wolfSSL source tree (autotools or CMake build)

## Building and running

```sh
git clone --recurse-submodules https://github.com/youruser/wychcheck.git
cd wychcheck

export WOLFSSL_DIR=/path/to/wolfssl

cmake -B build
cmake --build build
./build/wychcheck
```

The Wycheproof test vectors are included as a git submodule. To use a different checkout, set `WYCHEPROOF_DIR`:

```sh
WYCHEPROOF_DIR=/path/to/wycheproof ./build/wychcheck
```

The tool scans `testvectors_v1/` (falling back to `testvectors/`) for JSON test vector files, matches each file's schema to a test runner, and reports per-file and overall results:

```
wychcheck: testing wolfSSL against Wycheproof vectors
vectors: /path/to/wycheproof/testvectors_v1

PASS  aes_gcm_test.json                                    42 passed, 0 skipped
FAIL  ecdsa_secp256r1_sha256_test.json                     128 passed, 3 FAILED, 0 skipped
SKIP  primality_test.json                                  (not compiled)

--- summary ---
files tested: 45, skipped: 12
vectors: 4231 passed, 3 failed, 87 skipped
```

The exit code is 0 if all vectors pass, 1 if any fail, or 2 on setup errors.

## Project structure

```
src/
  main.c          -- entry point, scans test vector directory
  runner.h        -- shared types, helpers, and runner declarations
  hex.c / hex.h   -- hex encoding/decoding
  cjson/          -- vendored cJSON library
  runners/        -- one file per test schema (aead.c, ecdsa.c, etc.)
```
