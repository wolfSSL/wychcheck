# wychcheck: Wycheproof test vectors for wolfSSL

Google's [Project Wycheproof](https://github.com/google/wycheproof) provides
over 50,000 cryptographic test vectors designed to catch known weaknesses in
crypto implementations. These vectors have found bugs in OpenSSL, BoringSSL,
Go's crypto library, and Java's JCE providers.

wolfSSL has had some Wycheproof vectors scattered through its existing test
suite, but coverage was partial and ad-hoc. wychcheck formalizes this by
running the complete Wycheproof corpus against wolfcrypt systematically.

## What wychcheck does

wychcheck links against a built wolfSSL and runs every applicable Wycheproof
vector against wolfcrypt. It covers 13 test schemas: AEAD (AES-GCM, AES-CCM,
AES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305), MAC (HMAC, AES-CMAC),
HKDF, AES-CBC, AES-XTS, AES-KW, ECDH, ECDSA (DER and P1363), EdDSA
(Ed25519, Ed448), XDH (X25519, X448), and RSA (PKCS#1 v1.5, OAEP, PSS).

It reads `wolfssl/options.h` and automatically skips algorithms that aren't
compiled in, so it works with any wolfSSL configuration.

## What we found

Running against wolfSSL master (`--enable-all`) on x86-64:

**X25519 non-canonical output (security).**
The x86-64 assembly for `curve25519_x64` and `curve25519_avx2` has a final
reduction that can leave bit 255 set in the shared secret. The second
reduction pass clears the high bit, adds a correction, but the carry from
the addition can re-set it. This is the same class of bug fixed in wolfSSL
PR #1671 (2018) for intermediate mul/sq operations, but the final output
reduction was missed. Triggered by two Wycheproof edge-case vectors where
the shared secret is a small value.

**Empty plaintext rejected across multiple APIs.**
`wc_ChaCha20Poly1305_Decrypt`, `wc_XChaCha20Poly1305_Decrypt`,
`wc_AesEaxDecryptAuth`, and `wc_SignatureVerify` all return `BAD_FUNC_ARG`
when the plaintext/message length is zero. Zero-length plaintext is valid
for all of these: AEAD with empty plaintext is authentication-only, and
signing an empty message is well-defined (the hash of "" is well-defined).

**RSA-OAEP rejects empty plaintext.**
`RsaPublicEncryptEx` rejected `inLen==0` unconditionally. RFC 8017 permits
zero-length OAEP messages.

All of these have fixes on branches in our wolfSSL fork, and several have
been submitted upstream.

## Run it yourself

```sh
git clone --recurse-submodules https://github.com/wolfSSL/wychcheck.git
cd wychcheck

export WOLFSSL_DIR=/path/to/your/built/wolfssl

cmake -B build
cmake --build build
./build/wychcheck
```

The Wycheproof vectors are included as a submodule. The exit code is 0 if
everything passes, 1 if any vector fails. That's it.

The point of wychcheck is that you run it against **your** wolfSSL build,
with **your** `./configure` flags, on **your** hardware. A vector that
passes in CI with `--enable-all` on x86-64 might fail on your ARM board
with a minimal config. The only way to know is to run it.
