#include "runner.h"

/*
 * Runners for NIST ACVP ML-KEM test vectors (FIPS 203).
 *
 * The merged JSON files (produced by tools/merge_acvp.py) combine
 * prompt.json + expectedResults.json into a single self-contained file.
 * Two operations are covered:
 *
 *   mlkem_acvp_keygen_test.json    — key generation from (d, z) seeds
 *   mlkem_acvp_encapdecap_test.json — encapsulation, decapsulation,
 *                                     and key validation
 *
 * Feature guard: WOLFSSL_HAVE_MLKEM
 */

#ifdef WOLFSSL_HAVE_MLKEM
#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* Map ACVP parameterSet string to wolfssl level constant */
static int acvp_mlkem_level(cJSON *group)
{
    cJSON *ps = cJSON_GetObjectItem(group, "parameterSet");
    if (!ps || !cJSON_IsString(ps)) return -1;
    if (strcmp(ps->valuestring, "ML-KEM-512")  == 0) return WC_ML_KEM_512;
    if (strcmp(ps->valuestring, "ML-KEM-768")  == 0) return WC_ML_KEM_768;
    if (strcmp(ps->valuestring, "ML-KEM-1024") == 0) return WC_ML_KEM_1024;
    return -1;
}
#endif /* WOLFSSL_HAVE_MLKEM */


/* ------------------------------------------------------------------
 * KEY GENERATION  (mlkem_acvp_keygen_test.json)
 *
 * NIST provides d and z separately (each 32 bytes).  wolfSSL's
 * wc_MlKemKey_MakeKeyWithRandom() takes the 64-byte concatenation d||z,
 * matching the FIPS 203 §7.1 ML-KEM.KeyGen() call sequence where d is
 * used first (K-PKE.KeyGen) and z is appended to form the full dk.
 * The output is compared byte-exact to the expected ek and dk.
 * ------------------------------------------------------------------ */

test_result_t run_mlkem_acvp_keygen(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_MLKEM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level = acvp_mlkem_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *d = NULL, *z = NULL, *exp_ek = NULL, *exp_dk = NULL;
            size_t   d_len, z_len, exp_ek_len, exp_dk_len;
            uint8_t  seed[64];   /* d || z */
            uint8_t *got_ek = NULL, *got_dk = NULL;
            word32   got_ek_len, got_dk_len;
            MlKemKey key;
            int      key_inited = 0, ret;

            d      = get_hex(tc, "d",  &d_len);
            z      = get_hex(tc, "z",  &z_len);
            exp_ek = get_hex(tc, "ek", &exp_ek_len);
            exp_dk = get_hex(tc, "dk", &exp_dk_len);

            if (!d || !z || !exp_ek || !exp_dk ||
                d_len != 32 || z_len != 32) {
                res.skipped++;
                goto keygen_next;
            }

            /* Construct the 64-byte seed: d comes first, z second.
             * wc_MlKemKey_MakeKeyWithRandom reads d = seed[0:32] and
             * z = seed[32:64], matching FIPS 203 §7.1 input order. */
            memcpy(seed,      d, 32);
            memcpy(seed + 32, z, 32);

            ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto keygen_next; }
            key_inited = 1;

            ret = wc_MlKemKey_MakeKeyWithRandom(&key, seed, 64);
            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-KEM keygen from seed failed (%d)", ret);
                goto keygen_next;
            }

            wc_MlKemKey_PublicKeySize(&key,  &got_ek_len);
            wc_MlKemKey_PrivateKeySize(&key, &got_dk_len);
            got_ek = (uint8_t *)malloc(got_ek_len);
            got_dk = (uint8_t *)malloc(got_dk_len);
            if (!got_ek || !got_dk) { res.skipped++; goto keygen_next; }

            ret = wc_MlKemKey_EncodePublicKey(&key, got_ek, got_ek_len);
            if (ret == 0)
                ret = wc_MlKemKey_EncodePrivateKey(&key, got_dk, got_dk_len);

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-KEM key export failed (%d)", ret);
            } else if (got_ek_len != (word32)exp_ek_len ||
                       got_dk_len != (word32)exp_dk_len ||
                       memcmp(got_ek, exp_ek, exp_ek_len) != 0 ||
                       memcmp(got_dk, exp_dk, exp_dk_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-KEM keygen output mismatch");
            } else {
                res.passed++;
            }

        keygen_next:
            if (key_inited) wc_MlKemKey_Free(&key);
            free(d); free(z); free(exp_ek); free(exp_dk);
            free(got_ek); free(got_dk);
        }
    }
#else
    (void)root; (void)fname;
#endif /* WOLFSSL_HAVE_MLKEM */
    return res;
}


/* ------------------------------------------------------------------
 * ENCAPSULATION + DECAPSULATION  (mlkem_acvp_encapdecap_test.json)
 *
 * Four group function types:
 *
 *   "encapsulation":         ek + m  → c + k  (byte-exact)
 *   "decapsulation":         dk + c  → k      (byte-exact)
 *   "encapsulationKeyCheck": ek      → valid? (compare testPassed)
 *   "decapsulationKeyCheck": dk      → valid? (compare testPassed)
 *
 * Encapsulation is fully deterministic because ACVP provides the
 * 32-byte message seed m directly, so byte-exact comparison of c and k
 * is correct and catches rng-threading bugs that round-trip verify
 * would miss.
 *
 * Key-check groups test that the implementation correctly validates
 * key material per FIPS 203 §7.2/§7.3.  wc_MlKemKey_DecodePublicKey /
 * wc_MlKemKey_DecodePrivateKey return 0 for valid keys and non-zero for
 * invalid; that result is compared to the expected testPassed value.
 * ------------------------------------------------------------------ */

test_result_t run_mlkem_acvp_encapdecap(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_MLKEM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON      *fn_item;
        const char *fn;
        int         level;

        level = acvp_mlkem_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        fn_item = cJSON_GetObjectItem(group, "function");
        if (!fn_item || !cJSON_IsString(fn_item)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }
        fn = fn_item->valuestring;

        tests = cJSON_GetObjectItem(group, "tests");

        /* ---- encapsulation ---- */
        if (strcmp(fn, "encapsulation") == 0) {
            cJSON_ArrayForEach(tc, tests) {
                uint8_t *ek = NULL, *m = NULL, *exp_c = NULL, *exp_k = NULL;
                size_t   ek_len, m_len, exp_c_len, exp_k_len;
                uint8_t *got_c = NULL, *got_k = NULL;
                word32   got_c_len, got_k_len;
                MlKemKey key;
                int      key_inited = 0, ret;

                ek    = get_hex(tc, "ek", &ek_len);
                m     = get_hex(tc, "m",  &m_len);
                exp_c = get_hex(tc, "c",  &exp_c_len);
                exp_k = get_hex(tc, "k",  &exp_k_len);

                if (!ek || !m || !exp_c || !exp_k || m_len != 32) {
                    res.skipped++;
                    goto encap_next;
                }

                ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
                if (ret != 0) { res.skipped++; goto encap_next; }
                key_inited = 1;

                ret = wc_MlKemKey_DecodePublicKey(&key, ek, (word32)ek_len);
                if (ret != 0) { res.skipped++; goto encap_next; }

                wc_MlKemKey_CipherTextSize(&key,  &got_c_len);
                wc_MlKemKey_SharedSecretSize(&key, &got_k_len);
                got_c = (uint8_t *)malloc(got_c_len);
                got_k = (uint8_t *)malloc(got_k_len);
                if (!got_c || !got_k) { res.skipped++; goto encap_next; }

                ret = wc_MlKemKey_EncapsulateWithRandom(&key, got_c, got_k,
                                                        m, (int)m_len);
                if (ret != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM encap failed (%d)", ret);
                } else if (got_c_len != (word32)exp_c_len ||
                           got_k_len != (word32)exp_k_len ||
                           memcmp(got_c, exp_c, exp_c_len) != 0 ||
                           memcmp(got_k, exp_k, exp_k_len) != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM encap output mismatch");
                } else {
                    res.passed++;
                }

            encap_next:
                if (key_inited) wc_MlKemKey_Free(&key);
                free(ek); free(m); free(exp_c); free(exp_k);
                free(got_c); free(got_k);
            }

        /* ---- decapsulation ---- */
        } else if (strcmp(fn, "decapsulation") == 0) {
            cJSON_ArrayForEach(tc, tests) {
                uint8_t *dk = NULL, *ct = NULL, *exp_k = NULL;
                size_t   dk_len, ct_len, exp_k_len;
                uint8_t *got_k = NULL;
                word32   got_k_len;
                MlKemKey key;
                int      key_inited = 0, ret;

                dk    = get_hex(tc, "dk", &dk_len);
                ct    = get_hex(tc, "c",  &ct_len);
                exp_k = get_hex(tc, "k",  &exp_k_len);

                if (!dk || !ct || !exp_k) {
                    res.skipped++;
                    goto decap_next;
                }

                ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
                if (ret != 0) { res.skipped++; goto decap_next; }
                key_inited = 1;

                ret = wc_MlKemKey_DecodePrivateKey(&key, dk, (word32)dk_len);
                if (ret != 0) { res.skipped++; goto decap_next; }

                wc_MlKemKey_SharedSecretSize(&key, &got_k_len);
                got_k = (uint8_t *)malloc(got_k_len);
                if (!got_k) { res.skipped++; goto decap_next; }

                ret = wc_MlKemKey_Decapsulate(&key, got_k, ct, (word32)ct_len);
                if (ret != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM decap failed (%d)", ret);
                } else if (got_k_len != (word32)exp_k_len ||
                           memcmp(got_k, exp_k, exp_k_len) != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM decap k mismatch");
                } else {
                    res.passed++;
                }

            decap_next:
                if (key_inited) wc_MlKemKey_Free(&key);
                free(dk); free(ct); free(exp_k); free(got_k);
            }

        /* ---- encapsulation key check ---- */
        } else if (strcmp(fn, "encapsulationKeyCheck") == 0) {
            cJSON_ArrayForEach(tc, tests) {
                uint8_t *ek = NULL;
                size_t   ek_len;
                cJSON   *tp_item;
                int      expected_pass, got_pass;
                MlKemKey key;
                int      key_inited = 0, ret;

                tp_item = cJSON_GetObjectItem(tc, "testPassed");
                if (!tp_item || !cJSON_IsBool(tp_item)) {
                    res.skipped++;
                    continue;
                }
                expected_pass = cJSON_IsTrue(tp_item) ? 1 : 0;

                ek = get_hex(tc, "ek", &ek_len);
                if (!ek) { res.skipped++; continue; }

                ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
                if (ret != 0) { free(ek); res.skipped++; continue; }
                key_inited = 1;

                ret = wc_MlKemKey_DecodePublicKey(&key, ek, (word32)ek_len);
                got_pass = (ret == 0) ? 1 : 0;

                if (got_pass == expected_pass) {
                    res.passed++;
                } else {
                    res.failed++;
                    FAIL_TC(fname, tc,
                        "ML-KEM ekCheck: expected %s, got %s (ret=%d)",
                        expected_pass ? "valid" : "invalid",
                        got_pass      ? "valid" : "invalid", ret);
                }

                if (key_inited) wc_MlKemKey_Free(&key);
                free(ek);
            }

        /* ---- decapsulation key check ---- */
        } else if (strcmp(fn, "decapsulationKeyCheck") == 0) {
            cJSON_ArrayForEach(tc, tests) {
                uint8_t *dk = NULL;
                size_t   dk_len;
                cJSON   *tp_item;
                int      expected_pass, got_pass;
                MlKemKey key;
                int      key_inited = 0, ret;

                tp_item = cJSON_GetObjectItem(tc, "testPassed");
                if (!tp_item || !cJSON_IsBool(tp_item)) {
                    res.skipped++; continue;
                }
                expected_pass = cJSON_IsTrue(tp_item) ? 1 : 0;

                dk = get_hex(tc, "dk", &dk_len);
                if (!dk) { res.skipped++; continue; }

                ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
                if (ret != 0) { free(dk); res.skipped++; continue; }
                key_inited = 1;

                ret = wc_MlKemKey_DecodePrivateKey(&key, dk, (word32)dk_len);
                got_pass = (ret == 0) ? 1 : 0;

                if (got_pass == expected_pass) {
                    res.passed++;
                } else {
                    res.failed++;
                    FAIL_TC(fname, tc,
                        "ML-KEM dkCheck: expected %s, got %s (ret=%d)",
                        expected_pass ? "valid" : "invalid",
                        got_pass      ? "valid" : "invalid", ret);
                }

                if (key_inited) wc_MlKemKey_Free(&key);
                free(dk);
            }

        /* ---- unknown function type ---- */
        } else {
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
        }
    }
#else
    (void)root; (void)fname;
#endif /* WOLFSSL_HAVE_MLKEM */
    return res;
}
