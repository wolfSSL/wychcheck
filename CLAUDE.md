# CLAUDE.md

This file provides guidance to Claude Code when working on wolfcrypt-check.

## What This Is

wolfcrypt-check is a standalone C tool that tests wolfSSL wolfcrypt against
[Project Wycheproof](https://github.com/google/wycheproof) test vectors.
It links against a pre-built wolfSSL library, scans the Wycheproof JSON
test vector files, dispatches each file to the matching runner by schema
name, and reports per-file and overall pass/fail/skip counts.

## External Dependencies

| Dependency | Location | Notes |
|---|---|---|
| wolfSSL source tree | `~/wolfssl` | Must be *built* (autotools or CMake); set `WOLFSSL_DIR=~/wolfssl` |
| Wycheproof test vectors | `wycheproof/` submodule | Bundled; update with `git submodule update --remote wycheproof` |

## Build & Test

```bash
export WOLFSSL_DIR=~/wolfssl

# Build
cmake -B build
cmake --build build

# Run all Wycheproof vectors (uses bundled submodule)
./build/wolfcrypt-check

# Run against a different Wycheproof checkout
WYCHEPROOF_DIR=/path/to/wycheproof ./build/wolfcrypt-check

# Meta-tests: verify wolfcrypt-check itself correctly detects failures
./test/run_tests.sh
```

Exit codes: 0 = all tests passed, 1 = any test failed, 2 = infrastructure error.

CMake sets RPATH (not RUNPATH) so the binary uses the wolfssl from
`WOLFSSL_DIR` even if another version is installed system-wide.

## Architecture

```
src/main.c          scans testvectors_v1/ (falls back to testvectors/),
                    matches each JSON file's schema to a runner, dispatches

src/runners/
  aead.c            AES-GCM, AES-CCM, AES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305
  mac.c             HMAC, AES-CMAC, SipHash
  hkdf.c            HKDF
  ind_cpa.c         AES-CBC, AES-XTS
  keywrap.c         AES-KW
  ecdh.c            ECDH
  ecdsa.c           ECDSA (DER)
  ecdsa_p1363.c     ECDSA (P1363 / IEEE)
  eddsa.c           Ed25519, Ed448
  xdh.c             X25519, X448
  rsa_sig.c         RSA PKCS#1 v1.5 signature verification
  rsa_oaep.c        RSA-OAEP decryption
  rsa_pss.c         RSA-PSS signature verification

src/runner.h        Shared types, helper inlines: hex decode, hash/MGF name
                    mapping, result predicates (is_valid / is_acceptable)
src/hex.c           Hex encode/decode
src/cjson/          Bundled cJSON (no external JSON dependency)
wycheproof/         Git submodule (google/wycheproof)
test/               Meta-tests and fixture vectors
```

## Conventions

- Each runner returns `test_result_t { passed, failed, skipped }`. Never
  modify return values to hide failures — a hidden failure is a bug.
- Gate tests on `wolfssl/options.h` feature macros so unsupported
  algorithms are skipped rather than hard-failed.
- `WOLFSSL_DIR` must point to a *built source tree*, not an install
  prefix. The library is found in `src/.libs/`, `lib/`, or `build/`
  under that path.
- Do not add external dependencies beyond cJSON (bundled) and wolfSSL.
- The Wycheproof submodule is the sole source of test vectors. Do not
  commit hand-crafted or derived vectors; use `wycheproof/` directly.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
