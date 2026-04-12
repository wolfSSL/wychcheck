# tools/

Scripts for generating and regenerating test vectors.

---

## make_rfc_vectors.py

Generates all files in `testvectors_rfc/` from RFC normative test vectors.
No network access required — all values are transcribed from the RFCs and
committed here as the source of truth.

```
python3 tools/make_rfc_vectors.py
```

### RFC sources

| Output file | RFC | Section | Description |
|---|---|---|---|
| `rfc8439_chacha20poly1305_test.json` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) | §2.8.2 | ChaCha20-Poly1305 AEAD |
| `rfc3394_aeskw_test.json` | [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394) | §4 | AES Key Wrap (6 cases, 128/192/256-bit KEKs) |
| `rfc7748_x25519_test.json` | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) | §6.1 | X25519 ECDH |
| `rfc7748_x448_test.json` | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) | §6.2 | X448 ECDH |
| `rfc5869_hkdf_test.json` | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | Appendix A | HKDF-SHA-256 (A.1, A.2, A.3) |
| `rfc8032_eddsa_test.json` | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | §7.1, §7.4 | Ed25519 (5 tests) + Ed448 (9 tests) |

**Ed448 note:** RFC 8032 §7.4 includes one Ed448ctx test case (tcId=8, message
"1 octet with context foo"). wolfssl's `wc_ed448_verify_msg` is called with
`NULL/0` context and cannot verify Ed448ctx signatures. That test case is
marked `"result": "acceptable"` so it counts as a pass regardless of the
wolfssl outcome.

---

## merge_acvp.py

Merges NIST ACVP raw `prompt.json` + `expectedResults.json` pairs (stored in
`testvectors_acvp/<Op>/`) into the self-contained JSON files that
wolfcrypt-check dispatches on.

```
python3 tools/merge_acvp.py
```

### ACVP vector provenance

Raw ACVP vectors are vendored under `testvectors_acvp/<Op>/`. They were
downloaded from the NIST ACVP Demo Server
([acvts.nist.gov](https://acvts.nist.gov/acvp/)) and are reproduced here
for reproducibility. The merged `*_test.json` files in `testvectors_acvp/`
are generated from them by `merge_acvp.py`.

| Raw directory | FIPS standard | Operation | Tests |
|---|---|---|---|
| `ML-DSA-keyGen-FIPS204/` | FIPS 204 (ML-DSA) | Key generation | 75 |
| `ML-DSA-sigVer-FIPS204/` | FIPS 204 (ML-DSA) | Signature verification | 180 |
| `ML-DSA-sigGen-FIPS204/` | FIPS 204 (ML-DSA) | Signature generation | 360 |
| `ML-KEM-keyGen-FIPS203/` | FIPS 203 (ML-KEM) | Key generation | 75 |
| `ML-KEM-encapDecap-FIPS203/` | FIPS 203 (ML-KEM) | Encap + decap + key validation | 165 |
| `SLH-DSA-keyGen-FIPS205/` | FIPS 205 (SLH-DSA) | Key generation | 1 |
| `SLH-DSA-sigVer-FIPS205/` | FIPS 205 (SLH-DSA) | Signature verification | 1 |
| `SLH-DSA-sigGen-FIPS205/` | FIPS 205 (SLH-DSA) | Signature generation | 2 |

The ML-DSA and ML-KEM vectors were requested directly from the NIST ACVP Demo
Server. The SLH-DSA vectors were sourced from BoringSSL's bundled NIST ACVP
test suite (`boringssl/util/fipstools/acvp/acvptool/test/`) — see the
`boringssl/` reference submodule; they originate from NIST ACVP session 565841
(downloaded 2024-12-03T23:29:11Z, vsIds 2716977–2716979). The vectors cover the
`SLH-DSA-SHA2-128s` parameter set only. wolfSSL implements the SHAKE variants
(`SLH-DSA-SHAKE-*`) but not the SHA2 variants, so these tests are skipped at
runtime until matching SHAKE vectors are added.

Each raw directory contains exactly two files from the NIST server:
- `prompt.json` — test group definitions and input values
- `expectedResults.json` — expected output values keyed by `tgId` / `tcId`

`merge_acvp.py` injects the expected values into the prompt test cases and
adds a `"schema"` field that the wolfcrypt-check dispatch table uses to
select the correct runner.

### Re-downloading ACVP vectors

If you need fresh vectors from NIST (e.g. after a wolfssl update or to get
larger test suites), use the NIST ACVP client to request new test sessions
against the ACVP Demo Server. Replace the `prompt.json` and
`expectedResults.json` files in the appropriate subdirectory, then re-run
`merge_acvp.py`.
