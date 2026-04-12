#include "runner.h"

/*
 * Runners for NIST ACVP SLH-DSA test vectors (FIPS 205).
 *
 * The merged JSON files (produced by tools/merge_acvp.py) combine
 * prompt.json + expectedResults.json into a single self-contained file.
 * Three operations are covered:
 *
 *   slhdsa_acvp_keygen_test.json  — key generation from seed components
 *   slhdsa_acvp_sigver_test.json  — signature verification
 *   slhdsa_acvp_siggen_test.json  — signature generation
 *
 * wolfSSL implements only the SHAKE variants of SLH-DSA (SLH-DSA-SHAKE-*).
 * Groups with SHA2-based parameter sets are skipped.
 *
 * Feature guard: WOLFSSL_HAVE_SLHDSA
 */

#ifdef WOLFSSL_HAVE_SLHDSA
#include <wolfssl/wolfcrypt/wc_slhdsa.h>

/* Map ACVP parameterSet string to wolfSSL SlhDsaParam enum.
 * Returns -1 for unsupported parameter sets (e.g. SHA2 variants,
 * which wolfSSL does not implement). */
static int acvp_slh_param(cJSON *group)
{
    cJSON *ps = cJSON_GetObjectItem(group, "parameterSet");
    if (!ps || !cJSON_IsString(ps)) return -1;
    const char *s = ps->valuestring;
    if (strcmp(s, "SLH-DSA-SHAKE-128s") == 0) return SLHDSA_SHAKE128S;
    if (strcmp(s, "SLH-DSA-SHAKE-128f") == 0) return SLHDSA_SHAKE128F;
    if (strcmp(s, "SLH-DSA-SHAKE-192s") == 0) return SLHDSA_SHAKE192S;
    if (strcmp(s, "SLH-DSA-SHAKE-192f") == 0) return SLHDSA_SHAKE192F;
    if (strcmp(s, "SLH-DSA-SHAKE-256s") == 0) return SLHDSA_SHAKE256S;
    if (strcmp(s, "SLH-DSA-SHAKE-256f") == 0) return SLHDSA_SHAKE256F;
    return -1;  /* SHA2 variants not supported by wolfSSL */
}

#endif /* WOLFSSL_HAVE_SLHDSA */


/* ------------------------------------------------------------------
 * KEY GENERATION  (slhdsa_acvp_keygen_test.json)
 *
 * ACVP provides the three seed components: skSeed, skPrf, pkSeed.
 * Expected outputs are pk and sk (FIPS 205 §9.1).
 * ------------------------------------------------------------------ */

test_result_t run_slhdsa_acvp_keygen(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_SLHDSA
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int param = acvp_slh_param(group);
        if (param < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *sk_seed = NULL, *sk_prf = NULL, *pk_seed = NULL;
            uint8_t *exp_pk = NULL, *exp_sk = NULL;
            size_t   sk_seed_len, sk_prf_len, pk_seed_len;
            size_t   exp_pk_len, exp_sk_len;
            uint8_t *got_pk = NULL, *got_sk = NULL;
            word32   got_pk_len, got_sk_len;
            SlhDsaKey key;
            int ret, pk_sz, sk_sz, key_inited = 0;

            sk_seed = get_hex(tc, "skSeed", &sk_seed_len);
            sk_prf  = get_hex(tc, "skPrf",  &sk_prf_len);
            pk_seed = get_hex(tc, "pkSeed", &pk_seed_len);
            exp_pk  = get_hex(tc, "pk",     &exp_pk_len);
            exp_sk  = get_hex(tc, "sk",     &exp_sk_len);

            if (!sk_seed || !sk_prf || !pk_seed || !exp_pk || !exp_sk) {
                res.skipped++;
                goto keygen_next;
            }

            ret = wc_SlhDsaKey_Init(&key, (enum SlhDsaParam)param,
                                    NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto keygen_next; }
            key_inited = 1;

            ret = wc_SlhDsaKey_MakeKeyWithRandom(&key,
                sk_seed, (word32)sk_seed_len,
                sk_prf,  (word32)sk_prf_len,
                pk_seed, (word32)pk_seed_len);
            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "SLH-DSA keygen failed (%d)", ret);
                goto keygen_next;
            }

            pk_sz = wc_SlhDsaKey_PublicSize(&key);
            sk_sz = wc_SlhDsaKey_PrivateSize(&key);
            if (pk_sz <= 0 || sk_sz <= 0) { res.skipped++; goto keygen_next; }

            got_pk_len = (word32)pk_sz;
            got_sk_len = (word32)sk_sz;
            got_pk = (uint8_t *)malloc(got_pk_len);
            got_sk = (uint8_t *)malloc(got_sk_len);
            if (!got_pk || !got_sk) { res.skipped++; goto keygen_next; }

            ret = wc_SlhDsaKey_ExportPublic(&key, got_pk, &got_pk_len);
            if (ret == 0)
                ret = wc_SlhDsaKey_ExportPrivate(&key, got_sk, &got_sk_len);

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "SLH-DSA export key failed (%d)", ret);
            } else if (got_pk_len != exp_pk_len || got_sk_len != exp_sk_len ||
                       memcmp(got_pk, exp_pk, exp_pk_len) != 0 ||
                       memcmp(got_sk, exp_sk, exp_sk_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "SLH-DSA keygen output mismatch");
            } else {
                res.passed++;
            }

        keygen_next:
            if (key_inited) wc_SlhDsaKey_Free(&key);
            free(sk_seed); free(sk_prf); free(pk_seed);
            free(exp_pk);  free(exp_sk);
            free(got_pk);  free(got_sk);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* WOLFSSL_HAVE_SLHDSA */
    return res;
}


/* ------------------------------------------------------------------
 * SIGNATURE VERIFICATION  (slhdsa_acvp_sigver_test.json)
 * ------------------------------------------------------------------ */

test_result_t run_slhdsa_acvp_sigver(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_HAVE_SLHDSA
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int param = acvp_slh_param(group);
        if (param < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *pk = NULL, *msg = NULL, *sig = NULL;
            size_t   pk_len, msg_len, sig_len;
            cJSON   *tp_item;
            int      expected_pass, got_pass, ret;
            SlhDsaKey key;
            int key_inited = 0;

            tp_item = cJSON_GetObjectItem(tc, "testPassed");
            if (!tp_item || !cJSON_IsBool(tp_item)) { res.skipped++; continue; }
            expected_pass = cJSON_IsTrue(tp_item) ? 1 : 0;

            pk  = get_hex(tc, "pk",        &pk_len);
            msg = get_hex(tc, "message",   &msg_len);
            sig = get_hex(tc, "signature", &sig_len);

            if (!pk || !msg || !sig) { res.skipped++; goto sigver_next; }

            ret = wc_SlhDsaKey_Init(&key, (enum SlhDsaParam)param,
                                    NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto sigver_next; }
            key_inited = 1;

            ret = wc_SlhDsaKey_ImportPublic(&key, pk, (word32)pk_len);
            if (ret != 0) { res.skipped++; goto sigver_next; }

            /* ctx = NULL/0: pure SLH-DSA with empty context */
            ret = wc_SlhDsaKey_Verify(&key, NULL, 0,
                msg, (word32)msg_len,
                sig, (word32)sig_len);

            got_pass = (ret == 0) ? 1 : 0;
            if (got_pass == expected_pass) {
                res.passed++;
            } else {
                res.failed++;
                FAIL_TC(fname, tc,
                    "SLH-DSA sigVer: expected %s, got %s (ret=%d)",
                    expected_pass ? "pass" : "fail",
                    got_pass      ? "pass" : "fail",
                    ret);
            }

        sigver_next:
            if (key_inited) wc_SlhDsaKey_Free(&key);
            free(pk); free(msg); free(sig);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* WOLFSSL_HAVE_SLHDSA */
    return res;
}


/* ------------------------------------------------------------------
 * SIGNATURE GENERATION  (slhdsa_acvp_siggen_test.json)
 *
 * deterministic=true  → wc_SlhDsaKey_SignDeterministic (addRnd = PK.seed)
 * deterministic=false → wc_SlhDsaKey_SignWithRandom with additionalRandomness
 *
 * No context used (pure SLH-DSA, ACVP vectors have no context field).
 * Output is compared byte-exact against the NIST expected signature.
 * ------------------------------------------------------------------ */

test_result_t run_slhdsa_acvp_siggen(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int param, deterministic;
        cJSON *det_item;

        param = acvp_slh_param(group);
        if (param < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        det_item = cJSON_GetObjectItem(group, "deterministic");
        deterministic = (det_item && cJSON_IsTrue(det_item)) ? 1 : 0;

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *sk = NULL, *msg = NULL, *add_rnd = NULL;
            uint8_t *exp_sig = NULL, *got_sig = NULL;
            size_t   sk_len, msg_len, add_rnd_len = 0, exp_sig_len;
            word32   got_sig_len;
            SlhDsaKey key;
            int ret, sig_sz, key_inited = 0;

            sk      = get_hex(tc, "sk",        &sk_len);
            msg     = get_hex(tc, "message",   &msg_len);
            exp_sig = get_hex(tc, "signature", &exp_sig_len);

            if (!sk || !msg || !exp_sig) { res.skipped++; goto siggen_next; }

            if (!deterministic) {
                cJSON *rnd_item = cJSON_GetObjectItem(tc, "additionalRandomness");
                if (!rnd_item || !cJSON_IsString(rnd_item)) {
                    res.skipped++;
                    goto siggen_next;
                }
                add_rnd = hex_decode(rnd_item->valuestring, &add_rnd_len);
                if (!add_rnd) { res.skipped++; goto siggen_next; }
            }

            ret = wc_SlhDsaKey_Init(&key, (enum SlhDsaParam)param,
                                    NULL, INVALID_DEVID);
            if (ret != 0) { res.skipped++; goto siggen_next; }
            key_inited = 1;

            ret = wc_SlhDsaKey_ImportPrivate(&key, sk, (word32)sk_len);
            if (ret != 0) { res.skipped++; goto siggen_next; }

            sig_sz = wc_SlhDsaKey_SigSize(&key);
            if (sig_sz <= 0) { res.skipped++; goto siggen_next; }
            got_sig_len = (word32)sig_sz;
            got_sig = (uint8_t *)malloc(got_sig_len);
            if (!got_sig) { res.skipped++; goto siggen_next; }

            if (deterministic) {
                ret = wc_SlhDsaKey_SignDeterministic(&key, NULL, 0,
                    msg, (word32)msg_len, got_sig, &got_sig_len);
            } else {
                ret = wc_SlhDsaKey_SignWithRandom(&key, NULL, 0,
                    msg, (word32)msg_len, got_sig, &got_sig_len,
                    add_rnd);
            }

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "SLH-DSA sigGen failed (%d)", ret);
            } else if (got_sig_len != exp_sig_len ||
                       memcmp(got_sig, exp_sig, exp_sig_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "SLH-DSA sigGen output mismatch");
            } else {
                res.passed++;
            }

        siggen_next:
            if (key_inited) wc_SlhDsaKey_Free(&key);
            free(sk); free(msg); free(add_rnd);
            free(exp_sig); free(got_sig);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* WOLFSSL_HAVE_SLHDSA && !WOLFSSL_SLHDSA_VERIFY_ONLY */
    return res;
}
