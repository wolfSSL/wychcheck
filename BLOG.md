# wychcheck: Wycheproof test vectors for wolfSSL

Google's [Project Wycheproof](https://github.com/google/wycheproof) provides
over 50,000 cryptographic test vectors designed to catch known weaknesses in
crypto implementations. These vectors have found bugs in OpenSSL, BoringSSL,
Go's crypto library, and Java's JCE providers.

wolfSSL has had used Wycheproof vectors scattered through its existing test
suite. This repo formalizes this by
running the complete Wycheproof corpus against wolfcrypt systematically.

## What Wychcheck does

This Wychcheck repo links against a built wolfSSL and runs every applicable Wycheproof
vector. It covers 13 test schemas: AEAD (AES-GCM, AES-CCM,
AES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305), MAC (HMAC, AES-CMAC),
HKDF, AES-CBC, AES-XTS, AES-KW, ECDH, ECDSA (DER and P1363), EdDSA
(Ed25519, Ed448), XDH (X25519, X448), and RSA (PKCS#1 v1.5, OAEP, PSS).

It reads `wolfssl/options.h` and automatically skips algorithms that aren't
compiled in, so it works with any wolfSSL configuration.

## Run it yourself

```sh
export WOLFSSL_DIR=/path/to/your/built/wolfssl

git clone --recurse-submodules https://github.com/wolfSSL/wychcheck.git
cd wychcheck

cmake -B build
cmake --build build
./build/wychcheck
```

The Wycheproof vectors are included as a submodule. The exit code is 0 if
everything passes, 1 if any vector fails. That's it.

The point of this Wychcheck repo is that you run it against **your** wolfSSL build,
with **your** `./configure` flags, on **your** hardware. A vector that
passes in CI with `--enable-all` on x86-64 might fail on your embedded board
with a customized config. The only way to know is to run it.

If it does fail, of course, immediately report it to us.

