#include "runner.h"

/*
 * Runners for NIST ACVP ML-DSA test vectors (FIPS 204).
 *
 * The merged JSON files (produced by tools/merge_acvp.py) combine
 * prompt.json + expectedResults.json into a single self-contained file.
 * Three operations are covered:
 *
 *   mldsa_acvp_keygen_test.json  — key generation from seed
 *   mldsa_acvp_sigver_test.json  — signature verification
 *   mldsa_acvp_siggen_test.json  — signature generation
 *
 * Groups with signatureInterface != "external" or preHash != "pure"
 * are skipped (internal / HashML-DSA modes are not exposed by wolfssl).
 */

#ifdef HAVE_DILITHIUM
#include <wolfssl/wolfcrypt/dilithium.h>

/* Map ACVP parameterSet string to wolfssl level constant */
static int acvp_level(cJSON *group)
{
    cJSON *ps = cJSON_GetObjectItem(group, "parameterSet");
    if (!ps || !cJSON_IsString(ps)) return -1;
    if (strcmp(ps->valuestring, "ML-DSA-44") == 0) return WC_ML_DSA_44;
    if (strcmp(ps->valuestring, "ML-DSA-65") == 0) return WC_ML_DSA_65;
    if (strcmp(ps->valuestring, "ML-DSA-87") == 0) return WC_ML_DSA_87;
    return -1;
}

/* Return 1 if this group uses the external/pure interface we can test.
 *
 * wolfssl's public API (wc_dilithium_sign_ctx_msg_with_seed and
 * wc_dilithium_verify_ctx_msg) implements only external-interface pure
 * ML-DSA (FIPS 204 §5.2/§3.3).  Two other modes exist in the ACVP suite
 * but are not reachable through the public API:
 *   - internal interface (signatureInterface="internal"): takes a 64-byte
 *     mu value directly rather than a message; requires Sign_internal which
 *     is an internal wolfssl function.
 *   - HashML-DSA (preHash="preHash"): pre-hashes the message with a
 *     specified hash before signing; wolfssl does not expose this variant.
 * Groups for these modes are skipped.  To add support, wolfssl would need
 * to expose wc_dilithium_sign_internal() and a HashML-DSA entry point. */
static int group_is_external_pure(cJSON *group)
{
    cJSON *iface = cJSON_GetObjectItem(group, "signatureInterface");
    cJSON *ph    = cJSON_GetObjectItem(group, "preHash");
    /* absent signatureInterface means internal; absent preHash means internal */
    if (!iface || !cJSON_IsString(iface)) return 0;
    if (strcmp(iface->valuestring, "external") != 0) return 0;
    if (!ph || !cJSON_IsString(ph)) return 0;
    if (strcmp(ph->valuestring, "pure") != 0) return 0;
    return 1;
}

#endif /* HAVE_DILITHIUM */


/* ------------------------------------------------------------------
 * KEY GENERATION  (mldsa_acvp_keygen_test.json)
 * ------------------------------------------------------------------ */

test_result_t run_mldsa_acvp_keygen(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef HAVE_DILITHIUM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level = acvp_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *seed = NULL, *exp_pk = NULL, *exp_sk = NULL;
            size_t    seed_len, exp_pk_len, exp_sk_len;
            uint8_t  *got_pk = NULL, *got_sk = NULL;
            word32    got_pk_len, got_sk_len;
            dilithium_key key;
            int ret, pk_sz, sk_sz;

            seed   = get_hex(tc, "seed", &seed_len);
            exp_pk = get_hex(tc, "pk",   &exp_pk_len);
            exp_sk = get_hex(tc, "sk",   &exp_sk_len);

            if (!seed || !exp_pk || !exp_sk || seed_len != 32) {
                res.skipped++;
                goto keygen_next;
            }

            wc_dilithium_init(&key);
            ret = wc_dilithium_set_level(&key, (byte)level);
            if (ret != 0) { wc_dilithium_free(&key); res.skipped++; goto keygen_next; }

            ret = wc_dilithium_make_key_from_seed(&key, seed);
            if (ret != 0) {
                wc_dilithium_free(&key);
                res.failed++;
                FAIL_TC(fname, tc, "ML-DSA keygen from seed failed (%d)", ret);
                goto keygen_next;
            }

            pk_sz = wc_dilithium_pub_size(&key);
            sk_sz = wc_dilithium_priv_size(&key);
            if (pk_sz <= 0 || sk_sz <= 0) {
                wc_dilithium_free(&key);
                res.skipped++;
                goto keygen_next;
            }
            got_pk_len = (word32)pk_sz;
            got_sk_len = (word32)sk_sz;
            got_pk = (uint8_t *)malloc(got_pk_len);
            got_sk = (uint8_t *)malloc(got_sk_len);
            if (!got_pk || !got_sk) {
                wc_dilithium_free(&key);
                res.skipped++;
                goto keygen_next;
            }

            ret = wc_dilithium_export_public(&key, got_pk, &got_pk_len);
            if (ret == 0)
                ret = wc_dilithium_export_private(&key, got_sk, &got_sk_len);
            wc_dilithium_free(&key);

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-DSA export key failed (%d)", ret);
            } else if (got_pk_len != exp_pk_len || got_sk_len != exp_sk_len ||
                       memcmp(got_pk, exp_pk, exp_pk_len) != 0 ||
                       memcmp(got_sk, exp_sk, exp_sk_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-DSA keygen output mismatch");
            } else {
                res.passed++;
            }

        keygen_next:
            free(seed); free(exp_pk); free(exp_sk);
            free(got_pk); free(got_sk);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_DILITHIUM */
    return res;
}


/* ------------------------------------------------------------------
 * SIGNATURE VERIFICATION  (mldsa_acvp_sigver_test.json)
 *
 * Skips internal and preHash groups (not exposed by wolfssl).
 * ------------------------------------------------------------------ */

test_result_t run_mldsa_acvp_sigver(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef HAVE_DILITHIUM
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level;

        if (!group_is_external_pure(group)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        level = acvp_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *pk = NULL, *msg = NULL, *ctx = NULL, *sig = NULL;
            size_t   pk_len, msg_len, ctx_len = 0, sig_len;
            cJSON   *tp_item, *ctx_item;
            int      expected_pass, stat = 0, ret;
            dilithium_key key;

            /* ACVP uses a two-way boolean (testPassed: true/false).
             * Wycheproof uses three-way (valid/invalid/acceptable).
             * There is no "acceptable" category in ACVP; every test case
             * must either pass or fail with no ambiguity. */
            tp_item = cJSON_GetObjectItem(tc, "testPassed");
            if (!tp_item || !cJSON_IsBool(tp_item)) { res.skipped++; continue; }
            expected_pass = cJSON_IsTrue(tp_item) ? 1 : 0;

            pk  = get_hex(tc, "pk",        &pk_len);
            msg = get_hex(tc, "message",   &msg_len);
            sig = get_hex(tc, "signature", &sig_len);

            ctx_item = cJSON_GetObjectItem(tc, "context");
            if (ctx_item && cJSON_IsString(ctx_item))
                ctx = hex_decode(ctx_item->valuestring, &ctx_len);

            /* Init before any goto so sigver_next always frees key safely. */
            wc_dilithium_init(&key);

            if (!pk || !msg || !sig || ctx_len > 255) {
                res.skipped++;
                goto sigver_next;
            }

            ret = wc_dilithium_set_level(&key, (byte)level);
            if (ret == 0)
                ret = wc_dilithium_import_public(pk, (word32)pk_len, &key);

            if (ret != 0) {
                res.skipped++;
                goto sigver_next;
            }

            ret = wc_dilithium_verify_ctx_msg(
                sig, (word32)sig_len,
                ctx, (byte)ctx_len,
                msg, (word32)msg_len,
                &stat, &key);

            {
                int got_pass = (ret == 0 && stat == 1) ? 1 : 0;
                if (got_pass == expected_pass)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc,
                        "ML-DSA sigVer: expected %s, got %s (ret=%d stat=%d)",
                        expected_pass ? "pass" : "fail",
                        got_pass      ? "pass" : "fail",
                        ret, stat);
                }
            }

        sigver_next:
            wc_dilithium_free(&key);
            free(pk); free(msg); free(ctx); free(sig);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_DILITHIUM */
    return res;
}


/* ------------------------------------------------------------------
 * SIGNATURE GENERATION  (mldsa_acvp_siggen_test.json)
 *
 * Skips internal and preHash groups.
 * For deterministic groups: rnd = 0^32.
 * For non-deterministic groups: rnd is provided per test case.
 *
 * Output is compared byte-exact to the NIST expected signature.
 * Byte-exact is correct here (unlike the Wycheproof sign_seed/noseed
 * runners which use round-trip verify): ACVP siggen is fully
 * deterministic because the server provides an explicit 32-byte rnd.
 * wc_dilithium_sign_ctx_msg_with_seed consumes rnd directly, so the
 * output is completely determined by (sk, msg, ctx, rnd).  Byte-exact
 * comparison is tighter than round-trip — it catches off-by-one bugs
 * in rnd handling that a round-trip verify would miss.
 * ------------------------------------------------------------------ */

test_result_t run_mldsa_acvp_siggen(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
    static const byte zeros32[32] = {0};
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        int level;
        cJSON *det_item;
        int deterministic;

        if (!group_is_external_pure(group)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        level = acvp_level(group);
        if (level < 0) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        det_item = cJSON_GetObjectItem(group, "deterministic");
        deterministic = (det_item && cJSON_IsTrue(det_item)) ? 1 : 0;

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t  *sk = NULL, *msg = NULL, *ctx = NULL;
            uint8_t  *rnd_bytes = NULL, *exp_sig = NULL, *got_sig = NULL;
            size_t    sk_len, msg_len, ctx_len = 0, exp_sig_len, rnd_len = 0;
            word32    got_sig_len;
            cJSON    *ctx_item, *rnd_item;
            const byte *rnd;
            int       ret, sig_sz;
            dilithium_key key;

            sk      = get_hex(tc, "sk",        &sk_len);
            msg     = get_hex(tc, "message",   &msg_len);
            exp_sig = get_hex(tc, "signature", &exp_sig_len);

            ctx_item = cJSON_GetObjectItem(tc, "context");
            if (ctx_item && cJSON_IsString(ctx_item))
                ctx = hex_decode(ctx_item->valuestring, &ctx_len);

            /* Init before any goto so siggen_next always frees key safely. */
            wc_dilithium_init(&key);

            if (!sk || !msg || !exp_sig || ctx_len > 255) {
                res.skipped++;
                goto siggen_next;
            }

            /* Both deterministic and non-deterministic cases flow through a
             * single wc_dilithium_sign_ctx_msg_with_seed call.  For
             * deterministic mode FIPS 204 specifies rnd = 0^32; for
             * non-deterministic mode the ACVP server provides an explicit
             * 32-byte rnd value.  rnd_bytes stays NULL for the deterministic
             * branch so the cleanup goto correctly skips free(NULL). */
            if (deterministic) {
                rnd = zeros32;
            } else {
                rnd_item = cJSON_GetObjectItem(tc, "rnd");
                if (!rnd_item || !cJSON_IsString(rnd_item)) {
                    res.skipped++;
                    goto siggen_next;
                }
                rnd_bytes = hex_decode(rnd_item->valuestring, &rnd_len);
                if (!rnd_bytes || rnd_len != 32) {
                    res.skipped++;
                    goto siggen_next;
                }
                rnd = rnd_bytes;
            }

            ret = wc_dilithium_set_level(&key, (byte)level);
            if (ret == 0)
                ret = wc_dilithium_import_private(sk, (word32)sk_len, &key);

            if (ret != 0) {
                res.skipped++;
                goto siggen_next;
            }

            sig_sz = wc_dilithium_sig_size(&key);
            if (sig_sz <= 0) {
                res.skipped++;
                goto siggen_next;
            }
            got_sig_len = (word32)sig_sz;
            got_sig = (uint8_t *)malloc(got_sig_len);
            if (!got_sig) {
                res.skipped++;
                goto siggen_next;
            }

            ret = wc_dilithium_sign_ctx_msg_with_seed(
                ctx, (byte)ctx_len,
                msg, (word32)msg_len,
                got_sig, &got_sig_len,
                &key, rnd);

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-DSA sigGen failed (%d)", ret);
            } else if (got_sig_len != exp_sig_len ||
                       memcmp(got_sig, exp_sig, exp_sig_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "ML-DSA sigGen output mismatch");
            } else {
                res.passed++;
            }

        siggen_next:
            wc_dilithium_free(&key);
            free(sk); free(msg); free(ctx);
            free(rnd_bytes); free(exp_sig); free(got_sig);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_DILITHIUM && !WOLFSSL_DILITHIUM_VERIFY_ONLY */
    return res;
}
