# wolfcrypt-check

Test [wolfSSL](https://www.wolfssl.com/) wolfcrypt against
[Project Wycheproof](https://github.com/google/wycheproof) and
[NIST ACVP](https://github.com/usnistgov/ACVP-Server) test vectors.

wolfcrypt-check is a standalone C project that links against a built wolfSSL
library and runs cryptographic test vectors against wolfcrypt APIs.  It
automatically adapts to wolfSSL's compile-time feature flags
(`wolfssl/options.h`), skipping tests for features that aren't compiled in.

## Supported algorithms

Covers 16 Wycheproof test schemas and 3 NIST ACVP ML-DSA schemas:

**Wycheproof:**
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
- **ML-DSA** (FIPS 204) -- signature verification, sign-from-seed, sign-from-key

**NIST ACVP (ML-DSA / FIPS 204):**
- Key generation -- byte-exact comparison against NIST expected output
- Signature verification -- compared against NIST `testPassed` result
- Signature generation -- byte-exact comparison against NIST expected output

## Prerequisites

- A C compiler and CMake (>= 3.10)
- A **built** wolfSSL source tree (autotools or CMake build)

## Building and running

```sh
git clone --recurse-submodules <repo-url>
cd wolfcrypt-check

export WOLFSSL_DIR=/path/to/wolfssl

cmake -B build
cmake --build build
./build/wolfcrypt-check
```

The Wycheproof test vectors are included as a git submodule pointing to
[google/wycheproof](https://github.com/google/wycheproof).  The NIST ACVP
ML-DSA vectors are bundled under `testvectors_acvp/` as pre-merged JSON files.

To use a different Wycheproof checkout:

```sh
WYCHEPROOF_DIR=/path/to/wycheproof ./build/wolfcrypt-check
```

To use a different ACVP vectors directory:

```sh
ACVP_DIR=/path/to/testvectors_acvp ./build/wolfcrypt-check
```

The tool scans the Wycheproof `testvectors_v1/` directory (falling back to
`testvectors/`), then scans the ACVP directory.  Each JSON file's `schema`
field is matched to a test runner.  Results are reported per file and in total:

```
wolfcrypt-check: testing wolfSSL against Wycheproof and ACVP vectors
wycheproof: /path/to/wycheproof/testvectors_v1
acvp:       /path/to/testvectors_acvp

PASS  aes_gcm_test.json                                    42 passed, 0 skipped
FAIL  ecdsa_secp256r1_sha256_test.json                     128 passed, 3 FAILED, 0 skipped
SKIP  primality_test.json                                  (not compiled)
PASS  mldsa_acvp_keygen_test.json                          75 passed, 0 skipped

--- summary ---
files tested: 48, skipped: 12
vectors: 4521 passed, 3 failed, 87 skipped
```

Exit code: 0 = all vectors pass, 1 = any vector failed, 2 = setup error.

## Regenerating ACVP merged vectors

The raw NIST ACVP prompt and expected-result files live in
`testvectors_acvp/ML-DSA-{keyGen,sigVer,sigGen}-FIPS204/`.  The pre-merged
files committed to this repo were produced by:

```sh
python3 tools/merge_acvp.py
```

Re-run this script after updating the raw files from the NIST ACVP Server.

## Project structure

```
src/
  main.c              -- entry point: scans Wycheproof then ACVP dirs
  runner.h            -- shared types, helpers, and runner declarations
  hex.c / hex.h       -- hex encoding/decoding
  cjson/              -- vendored cJSON library
  runners/            -- one file per test schema
    aead.c            -- AES-GCM, AES-CCM, AES-EAX, ChaCha20-Poly1305
    mac.c             -- HMAC, AES-CMAC, SipHash
    hkdf.c            -- HKDF
    ind_cpa.c         -- AES-CBC, AES-XTS
    keywrap.c         -- AES-KW
    ecdh.c            -- ECDH
    ecdsa.c           -- ECDSA (DER)
    ecdsa_p1363.c     -- ECDSA (P1363 / IEEE)
    eddsa.c           -- Ed25519, Ed448
    xdh.c             -- X25519, X448
    rsa_sig.c         -- RSA PKCS#1 v1.5 signature verification
    rsa_oaep.c        -- RSA-OAEP decryption
    rsa_pss.c         -- RSA-PSS signature verification
    mldsa.c           -- ML-DSA verify, sign-from-seed, sign-from-key
    mldsa_acvp.c      -- ML-DSA ACVP keygen, sigVer, sigGen

wycheproof/           -- git submodule: google/wycheproof
testvectors_acvp/     -- NIST ACVP ML-DSA vectors (raw + pre-merged)
tools/
  merge_acvp.py       -- merges ACVP prompt + expectedResults into one file
```

## Finding new coverage opportunities

There are three distinct places to look when checking whether upstream has
test vectors we should be running but aren't.

### 1. Wycheproof — new algorithms or schemas

The Wycheproof submodule is the primary source.  Update it and run:

```sh
git submodule update --remote wycheproof
./build/wolfcrypt-check 2>&1 | grep "no runner"
```

Each `SKIP … (no runner)` line names a JSON file whose `schema` field has no
registered runner.  That's a candidate for a new runner if wolfSSL implements
the algorithm.

Also grep for `(not compiled)`:

```sh
./build/wolfcrypt-check 2>&1 | grep "not compiled"
```

`(not compiled)` means the runner exists but the wolfSSL feature flag is
off — try rebuilding wolfSSL with the relevant `--enable-*` flag rather than
writing new code.

To see all schemas that appear in the vector files (including ones we skip):

```sh
python3 -c "
import json, glob, collections
schemas = collections.Counter()
for f in glob.glob('wycheproof/testvectors_v1/*.json'):
    try:
        d = json.load(open(f))
        schemas[d.get('schema','?')] += 1
    except Exception:
        pass
for s, n in sorted(schemas.items()):
    print(f'{n:4d}  {s}')
"
```

Compare that list against the runners registered in `src/main.c` to spot gaps.

### 2. NIST ACVP — new algorithm families

The NIST ACVP-Server repo is included as a git submodule at `acvp-server/`.
Browse its `gen-val/json-files/` directory for algorithm families not yet in
our `testvectors_acvp/`:

```sh
# update to latest ACVP-Server release
git submodule update --remote acvp-server

# see what NIST has
ls acvp-server/gen-val/json-files/ | sort

# compare with what we bundle
ls testvectors_acvp/
```

Any NIST directory whose algorithm wolfSSL supports is a candidate for
vendoring vectors.

### 3. BoringSSL bundled ACVP vectors

BoringSSL ships real NIST ACVP session responses that are usable offline.
They live at:
`util/fipstools/acvp/acvptool/test/` in the BoringSSL repo (one `.bz2` per
algorithm family).

This is how the SLH-DSA and ML-KEM ACVP vectors in this repo were obtained.
To check for new ones:

```sh
# list what BoringSSL bundles
gh api repos/google/boringssl/contents/util/fipstools/acvp/acvptool/test \
  --jq '.[].name' | sort

# compare with what we bundle
ls testvectors_acvp/
```

If BoringSSL has a `.bz2` for an algorithm we don't yet cover, extract and
merge it:

```sh
bzip2 -dk path/to/Algorithm.bz2      # produces Algorithm (JSON)
# edit tools/merge_acvp.py to add the new directory mapping
python3 tools/merge_acvp.py
```

See `tools/README.md` for provenance details and the merge workflow.

---

## Test vector sources

**Project Wycheproof**
- Repository: https://github.com/google/wycheproof
- Included as a git submodule at `wycheproof/`
- Wycheproof is a project by Google Security Team that tests crypto libraries
  against known attacks and edge cases.

**NIST ACVP ML-DSA vectors**
- Repository: https://github.com/usnistgov/ACVP-Server
- Vector path: `gen-val/json-files/ML-DSA-{keyGen,sigVer,sigGen}-FIPS204/`
- The NIST Automated Cryptographic Validation Protocol (ACVP) provides
  algorithm test vectors for FIPS-validated implementations.
- Specification: NIST FIPS 204, *Module-Lattice-Based Digital Signature
  Standard*, National Institute of Standards and Technology, 2024.
  https://doi.org/10.6028/NIST.FIPS.204
