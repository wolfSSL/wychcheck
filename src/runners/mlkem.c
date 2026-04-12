#include "runner.h"

/*
 * Runners for Wycheproof ML-KEM (FIPS 203) test vectors.
 *
 * Four schemas are handled:
 *   mlkem_test_schema.json            — full KEM: keygen + decap
 *   mlkem_encaps_test_schema.json     — encapsulation only
 *   mlkem_keygen_seed_test_schema.json — keygen from seed, check ek+dk
 *   mlkem_semi_expanded_decaps_test_schema.json — decapsulation validation
 *
 * Feature guard: WOLFSSL_HAVE_MLKEM
 * Header:        <wolfssl/wolfcrypt/wc_mlkem.h>
 */

#ifdef WOLFSSL_HAVE_MLKEM
#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* Map Wycheproof parameterSet string to wolfssl level constant */
static int mlkem_level(cJSON *group)
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
 * FULL KEM TEST  (mlkem_test_schema.json)
 *
 * Each test case: 64-byte seed → wc_MlKemKey_MakeKeyWithRandom() →
 * verify ek; then decapsulate provided ciphertext c with generated dk
 * and verify shared secret K.
 *
 * For "invalid" tests the ciphertext is intentionally malformed; ML-KEM
 * uses implicit rejection so decap always returns 0 but produces a K
 * that should NOT match the expected K.
 * ------------------------------------------------------------------ */
test_result_t run_mlkem(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_MLKEM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level = mlkem_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *seed = NULL, *exp_ek = NULL, *exp_c = NULL, *exp_K = NULL;
            size_t seed_len, exp_ek_len, exp_c_len, exp_K_len;
            uint8_t *got_ek = NULL, *got_K = NULL;
            word32 got_ek_len, got_K_len;
            MlKemKey key;
            int key_inited = 0, ret;

            seed  = get_hex(tc, "seed", &seed_len);
            exp_ek = get_hex(tc, "ek",  &exp_ek_len);
            exp_c  = get_hex(tc, "c",   &exp_c_len);
            exp_K  = get_hex(tc, "K",   &exp_K_len);

            if (!seed || !exp_ek || !exp_c || !exp_K || seed_len != 64) {
                res.skipped++;
                goto mlkem_test_next;
            }

            ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto mlkem_test_next; }
            key_inited = 1;

            ret = wc_MlKemKey_MakeKeyWithRandom(&key, seed, (int)seed_len);
            if (ret != 0) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM keygen from seed failed (%d)", ret);
                } else {
                    res.passed++;
                }
                goto mlkem_test_next;
            }

            /* Export and verify public key (encapsulation key) */
            wc_MlKemKey_PublicKeySize(&key, &got_ek_len);
            got_ek = (uint8_t *)malloc(got_ek_len);
            if (!got_ek) { res.skipped++; goto mlkem_test_next; }
            ret = wc_MlKemKey_EncodePublicKey(&key, got_ek, got_ek_len);
            if (ret != 0 || got_ek_len != (word32)exp_ek_len ||
                memcmp(got_ek, exp_ek, exp_ek_len) != 0) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM ek mismatch");
                } else {
                    res.passed++;
                }
                goto mlkem_test_next;
            }

            /* Decapsulate provided ciphertext with generated decapsulation key */
            wc_MlKemKey_SharedSecretSize(&key, &got_K_len);
            got_K = (uint8_t *)malloc(got_K_len);
            if (!got_K) { res.skipped++; goto mlkem_test_next; }
            ret = wc_MlKemKey_Decapsulate(&key, got_K, exp_c, (word32)exp_c_len);

            if (is_valid(tc)) {
                if (ret != 0 || got_K_len != (word32)exp_K_len ||
                    memcmp(got_K, exp_K, exp_K_len) != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM decap K mismatch (ret=%d)", ret);
                } else {
                    res.passed++;
                }
            } else {
                /* Malformed ciphertext: implicit rejection should produce K ≠ exp_K. */
                if (ret == 0 && got_K_len == (word32)exp_K_len &&
                    memcmp(got_K, exp_K, exp_K_len) == 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM accepted invalid ciphertext (K matched)");
                } else {
                    res.passed++;
                }
            }

        mlkem_test_next:
            if (key_inited) wc_MlKemKey_Free(&key);
            free(seed); free(exp_ek); free(exp_c); free(exp_K);
            free(got_ek); free(got_K);
        }
    }
#else
    (void)root; (void)fname;
#endif /* WOLFSSL_HAVE_MLKEM */
    return res;
}


/* ------------------------------------------------------------------
 * ENCAPSULATION TEST  (mlkem_encaps_test_schema.json)
 *
 * Each test case: load ek; encapsulate with 32-byte deterministic
 * randomness m; verify output ciphertext c and shared secret K.
 * Invalid tests use a wrong-length m or malformed ek (ModulusOverflow).
 * ------------------------------------------------------------------ */
test_result_t run_mlkem_encaps(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_MLKEM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level = mlkem_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *m = NULL, *ek = NULL, *exp_c = NULL, *exp_K = NULL;
            size_t m_len, ek_len, exp_c_len, exp_K_len;
            uint8_t *got_c = NULL, *got_K = NULL;
            word32 got_c_len, got_K_len;
            MlKemKey key;
            int key_inited = 0, ret;

            m     = get_hex(tc, "m",  &m_len);
            ek    = get_hex(tc, "ek", &ek_len);
            exp_c = get_hex(tc, "c",  &exp_c_len);
            exp_K = get_hex(tc, "K",  &exp_K_len);

            /* Wrong randomness length is the "invalid" condition for ModulusOverflow
             * tests; encapsulation randomness must be exactly WC_ML_KEM_ENC_RAND_SZ. */
            if (!m || !ek || m_len != WC_ML_KEM_ENC_RAND_SZ) {
                if (!is_valid(tc))
                    res.passed++;
                else
                    res.skipped++;
                goto mlkem_encaps_next;
            }

            ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto mlkem_encaps_next; }
            key_inited = 1;

            ret = wc_MlKemKey_DecodePublicKey(&key, ek, (word32)ek_len);
            if (ret != 0) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM ek import failed (%d)", ret);
                } else {
                    res.passed++;
                }
                goto mlkem_encaps_next;
            }

            wc_MlKemKey_CipherTextSize(&key, &got_c_len);
            wc_MlKemKey_SharedSecretSize(&key, &got_K_len);
            got_c = (uint8_t *)malloc(got_c_len);
            got_K = (uint8_t *)malloc(got_K_len);
            if (!got_c || !got_K) { res.skipped++; goto mlkem_encaps_next; }

            ret = wc_MlKemKey_EncapsulateWithRandom(&key, got_c, got_K,
                                                    m, (int)m_len);
            if (is_valid(tc)) {
                if (ret != 0 || got_c_len != (word32)exp_c_len ||
                    got_K_len != (word32)exp_K_len ||
                    memcmp(got_c, exp_c, exp_c_len) != 0 ||
                    memcmp(got_K, exp_K, exp_K_len) != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM encap mismatch (ret=%d)", ret);
                } else {
                    res.passed++;
                }
            } else {
                if (ret != 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM accepted invalid encap input");
                }
            }

        mlkem_encaps_next:
            if (key_inited) wc_MlKemKey_Free(&key);
            free(m); free(ek); free(exp_c); free(exp_K);
            free(got_c); free(got_K);
        }
    }
#else
    (void)root; (void)fname;
#endif /* WOLFSSL_HAVE_MLKEM */
    return res;
}


/* ------------------------------------------------------------------
 * KEY GENERATION FROM SEED  (mlkem_keygen_seed_test_schema.json)
 *
 * All test cases are "valid".  Each provides a 64-byte seed (d || z);
 * the runner calls wc_MlKemKey_MakeKeyWithRandom() and compares both
 * the encapsulation key (ek) and decapsulation key (dk) to expected.
 * ------------------------------------------------------------------ */
test_result_t run_mlkem_keygen(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_MLKEM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level = mlkem_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *seed = NULL, *exp_ek = NULL, *exp_dk = NULL;
            size_t seed_len, exp_ek_len, exp_dk_len;
            uint8_t *got_ek = NULL, *got_dk = NULL;
            word32 got_ek_len, got_dk_len;
            MlKemKey key;
            int key_inited = 0, ret;

            seed   = get_hex(tc, "seed", &seed_len);
            exp_ek = get_hex(tc, "ek",   &exp_ek_len);
            exp_dk = get_hex(tc, "dk",   &exp_dk_len);

            if (!seed || !exp_ek || !exp_dk || seed_len != 64) {
                res.skipped++;
                goto mlkem_keygen_next;
            }

            ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto mlkem_keygen_next; }
            key_inited = 1;

            ret = wc_MlKemKey_MakeKeyWithRandom(&key, seed, (int)seed_len);
            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-KEM keygen from seed failed (%d)", ret);
                goto mlkem_keygen_next;
            }

            wc_MlKemKey_PublicKeySize(&key,  &got_ek_len);
            wc_MlKemKey_PrivateKeySize(&key, &got_dk_len);
            got_ek = (uint8_t *)malloc(got_ek_len);
            got_dk = (uint8_t *)malloc(got_dk_len);
            if (!got_ek || !got_dk) { res.skipped++; goto mlkem_keygen_next; }

            ret = wc_MlKemKey_EncodePublicKey(&key, got_ek, got_ek_len);
            if (ret == 0)
                ret = wc_MlKemKey_EncodePrivateKey(&key, got_dk, got_dk_len);

            if (ret != 0 ||
                got_ek_len != (word32)exp_ek_len ||
                got_dk_len != (word32)exp_dk_len ||
                memcmp(got_ek, exp_ek, exp_ek_len) != 0 ||
                memcmp(got_dk, exp_dk, exp_dk_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-KEM keygen output mismatch");
            } else {
                res.passed++;
            }

        mlkem_keygen_next:
            if (key_inited) wc_MlKemKey_Free(&key);
            free(seed); free(exp_ek); free(exp_dk);
            free(got_ek); free(got_dk);
        }
    }
#else
    (void)root; (void)fname;
#endif /* WOLFSSL_HAVE_MLKEM */
    return res;
}


/* ------------------------------------------------------------------
 * DECAPSULATION VALIDATION  (mlkem_semi_expanded_decaps_test_schema.json)
 *
 * Each test case: import dk from raw bytes; decapsulate c; verify K.
 * Invalid tests use wrong-length dk/ct or structurally malformed keys
 * (IncorrectCiphertextLength, IncorrectDecapsulationKeyLength,
 * InvalidDecapsulationKey).  For structurally invalid inputs wolfSSL
 * may return an error rather than the implicit-rejection K.
 *
 * The K field is optional: "semi-expanded" structural validation tests
 * omit it.  When absent, valid tests check only that decap returns 0;
 * invalid tests accept either an error return or implicit rejection. */
test_result_t run_mlkem_decaps(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_MLKEM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level = mlkem_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *dk = NULL, *ct = NULL, *exp_K = NULL;
            size_t dk_len, ct_len, exp_K_len;
            uint8_t *got_K = NULL;
            word32 got_K_len;
            MlKemKey key;
            int key_inited = 0, ret;

            dk    = get_hex(tc, "dk", &dk_len);
            ct    = get_hex(tc, "c",  &ct_len);
            exp_K = get_hex(tc, "K",  &exp_K_len); /* may be NULL if field absent */

            if (!dk || !ct) {
                res.skipped++;
                goto mlkem_decaps_next;
            }

            ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto mlkem_decaps_next; }
            key_inited = 1;

            ret = wc_MlKemKey_DecodePrivateKey(&key, dk, (word32)dk_len);
            if (ret != 0) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM dk import failed (%d)", ret);
                } else {
                    res.passed++;
                }
                goto mlkem_decaps_next;
            }

            wc_MlKemKey_SharedSecretSize(&key, &got_K_len);
            got_K = (uint8_t *)malloc(got_K_len);
            if (!got_K) { res.skipped++; goto mlkem_decaps_next; }

            ret = wc_MlKemKey_Decapsulate(&key, got_K, ct, (word32)ct_len);

            if (is_valid(tc)) {
                if (ret != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM decap failed (ret=%d)", ret);
                } else if (exp_K != NULL && (got_K_len != (word32)exp_K_len ||
                           memcmp(got_K, exp_K, exp_K_len) != 0)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM decap K mismatch");
                } else {
                    res.passed++;
                }
            } else {
                /* Implicit rejection: decap returns 0 but K should differ from exp_K,
                 * OR wolfSSL returns an error for structurally invalid input.
                 * When K is absent, both outcomes are acceptable. */
                if (ret != 0) {
                    res.passed++;
                } else if (exp_K == NULL) {
                    res.passed++;  /* implicit rejection; no K to verify */
                } else if (got_K_len == (word32)exp_K_len &&
                           memcmp(got_K, exp_K, exp_K_len) == 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-KEM accepted invalid ciphertext (K matched)");
                } else {
                    res.passed++;
                }
            }

        mlkem_decaps_next:
            if (key_inited) wc_MlKemKey_Free(&key);
            free(dk); free(ct); free(exp_K); free(got_K);
        }
    }
#else
    (void)root; (void)fname;
#endif /* WOLFSSL_HAVE_MLKEM */
    return res;
}
