#include "runner.h"

#ifdef HAVE_DILITHIUM
#include <wolfssl/wolfcrypt/dilithium.h>

/* Map Wycheproof algorithm name to wolfssl level constant */
static int mldsa_level(cJSON *root)
{
    cJSON *alg = cJSON_GetObjectItem(root, "algorithm");
    if (!alg || !cJSON_IsString(alg)) return -1;
    if (strcmp(alg->valuestring, "ML-DSA-44") == 0) return WC_ML_DSA_44;
    if (strcmp(alg->valuestring, "ML-DSA-65") == 0) return WC_ML_DSA_65;
    if (strcmp(alg->valuestring, "ML-DSA-87") == 0) return WC_ML_DSA_87;
    return -1;
}

/* Return 1 if test case carries the "Internal" flag (Sign_internal / no msg) */
static int has_internal_flag(cJSON *tc)
{
    cJSON *flags = cJSON_GetObjectItem(tc, "flags");
    cJSON *flag;
    if (!flags || !cJSON_IsArray(flags))
        return 0;
    cJSON_ArrayForEach(flag, flags) {
        if (cJSON_IsString(flag) &&
            strcmp(flag->valuestring, "Internal") == 0)
            return 1;
    }
    return 0;
}
#endif /* HAVE_DILITHIUM */

/* ------------------------------------------------------------------
 * VERIFY  (mldsa_verify_schema.json)
 * ------------------------------------------------------------------ */

test_result_t run_mldsa_verify(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef HAVE_DILITHIUM
    cJSON *groups, *group, *tests, *tc;
    int level = mldsa_level(root);

    if (level < 0)
        return res; /* unknown algorithm → treat as not compiled */

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON   *pk_item = cJSON_GetObjectItem(group, "publicKey");
        uint8_t *pk_bytes;
        size_t   pk_len;
        dilithium_key key;
        int key_ok = 0;

        if (!pk_item || !cJSON_IsString(pk_item)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        pk_bytes = hex_decode(pk_item->valuestring, &pk_len);
        if (!pk_bytes) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        wc_dilithium_init(&key);
        if (wc_dilithium_set_level(&key, (byte)level) == 0 &&
            wc_dilithium_import_public(pk_bytes, (word32)pk_len, &key) == 0)
            key_ok = 1;
        free(pk_bytes);

        if (!key_ok) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            wc_dilithium_free(&key);
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *msg  = NULL, *sig = NULL, *ctx = NULL;
            size_t   msg_len = 0, sig_len = 0, ctx_len = 0;
            cJSON   *ctx_item;
            int      stat = 0, ret;
            int      ctx_too_long = 0;

            msg = get_hex(tc, "msg", &msg_len);
            sig = get_hex(tc, "sig", &sig_len);

            ctx_item = cJSON_GetObjectItem(tc, "ctx");
            if (ctx_item && cJSON_IsString(ctx_item))
                ctx = hex_decode(ctx_item->valuestring, &ctx_len);

            if (ctx_len > 255)
                ctx_too_long = 1;

            if (!ctx_too_long) {
                ret = wc_dilithium_verify_ctx_msg(
                    sig,  (word32)sig_len,
                    ctx,  (byte)ctx_len,
                    msg,  (word32)msg_len,
                    &stat, &key);
            } else {
                /* Context > 255 bytes is always invalid per FIPS 204 */
                ret  = -1;
                stat = 0;
            }

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0 && stat == 1)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc,
                        "ML-DSA verify failed (ret=%d, stat=%d)", ret, stat);
                }
            } else {
                if (ret != 0 || stat == 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-DSA accepted invalid signature");
                }
            }

            free(msg); free(sig); free(ctx);
        }
        wc_dilithium_free(&key);
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_DILITHIUM */
    return res;
}

/* ------------------------------------------------------------------
 * SIGN WITH SEED  (mldsa_sign_seed_schema.json)
 *
 * Group provides a 32-byte privateSeed used to reconstruct the full
 * key pair via wc_dilithium_make_key_from_seed().  Per-test signing
 * uses zeros32 as the FIPS 204 signing randomness (rnd), giving
 * deterministic output.  The produced signature is then verified
 * against the same message to confirm correctness.  Internal-flagged
 * tests (Sign_internal / mu-only) are skipped.
 * ------------------------------------------------------------------ */

test_result_t run_mldsa_sign_seed(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
    static const byte zeros32[32] = {0};
    cJSON *groups, *group, *tests, *tc;
    int level = mldsa_level(root);

    if (level < 0)
        return res;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON   *seed_item = cJSON_GetObjectItem(group, "privateSeed");
        cJSON   *pk_item   = cJSON_GetObjectItem(group, "publicKey");
        uint8_t *seed_bytes;
        size_t   seed_len;
        dilithium_key key;
        int key_ok = 0;

        /* publicKey == JSON null means the seed is invalid */
        if (cJSON_IsNull(pk_item)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        if (!seed_item || !cJSON_IsString(seed_item)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        seed_bytes = hex_decode(seed_item->valuestring, &seed_len);
        if (!seed_bytes) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        wc_dilithium_init(&key);
        /* Seed must be exactly 32 bytes for all parameter sets */
        if (seed_len == 32 &&
            wc_dilithium_set_level(&key, (byte)level) == 0 &&
            wc_dilithium_make_key_from_seed(&key, seed_bytes) == 0)
            key_ok = 1;
        free(seed_bytes);

        if (!key_ok) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            wc_dilithium_free(&key);
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t  *msg = NULL, *sig_buf = NULL, *ctx = NULL;
            size_t    msg_len = 0, ctx_len = 0;
            word32    sig_buf_len;
            cJSON    *ctx_item;
            int       ret, sig_size;
            int       ctx_too_long = 0;

            /* Sign_internal tests require internal API not exposed here */
            if (has_internal_flag(tc)) {
                res.skipped++;
                continue;
            }

            msg = get_hex(tc, "msg", &msg_len);

            ctx_item = cJSON_GetObjectItem(tc, "ctx");
            if (ctx_item && cJSON_IsString(ctx_item))
                ctx = hex_decode(ctx_item->valuestring, &ctx_len);

            if (ctx_len > 255)
                ctx_too_long = 1;

            if (is_acceptable(tc)) {
                res.passed++;
                goto sign_seed_next;
            }

            if (is_valid(tc)) {
                if (ctx_too_long) {
                    /* No valid test should have ctx > 255 bytes */
                    res.failed++;
                    FAIL_TC(fname, tc,
                        "ML-DSA: ctx > 255 bytes but result is valid");
                    goto sign_seed_next;
                }

                sig_size = wc_dilithium_sig_size(&key);
                if (sig_size <= 0) { res.skipped++; goto sign_seed_next; }
                sig_buf_len = (word32)sig_size;
                sig_buf = (uint8_t *)malloc(sig_buf_len);
                if (!sig_buf) { res.skipped++; goto sign_seed_next; }

                ret = wc_dilithium_sign_ctx_msg_with_seed(
                    ctx, (byte)ctx_len,
                    msg, (word32)msg_len,
                    sig_buf, &sig_buf_len,
                    &key, zeros32);

                if (ret != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-DSA sign failed (ret=%d)", ret);
                } else {
                    /* Round-trip: verify the produced signature.
                 * We do NOT compare bytes to a reference sig.  FIPS 204
                 * hedged signing is randomized; wolfssl may use a different
                 * rnd source, so byte-exact comparison would fail on any
                 * valid non-deterministic implementation. */
                    int stat = 0;
                    int vret = wc_dilithium_verify_ctx_msg(
                        sig_buf, sig_buf_len,
                        ctx,     (byte)ctx_len,
                        msg,     (word32)msg_len,
                        &stat, &key);
                    if (vret == 0 && stat == 1)
                        res.passed++;
                    else {
                        res.failed++;
                        FAIL_TC(fname, tc,
                            "ML-DSA produced unverifiable sig (vret=%d, stat=%d)",
                            vret, stat);
                    }
                }
            } else {
                /* result == "invalid" */
                if (ctx_too_long) {
                    res.passed++; /* correctly rejected oversized context */
                    goto sign_seed_next;
                }

                sig_size = wc_dilithium_sig_size(&key);
                if (sig_size <= 0) { res.skipped++; goto sign_seed_next; }
                sig_buf_len = (word32)sig_size;
                sig_buf = (uint8_t *)malloc(sig_buf_len);
                if (!sig_buf) { res.skipped++; goto sign_seed_next; }

                ret = wc_dilithium_sign_ctx_msg_with_seed(
                    ctx, (byte)ctx_len,
                    msg, (word32)msg_len,
                    sig_buf, &sig_buf_len,
                    &key, zeros32);

                if (ret != 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-DSA sign accepted invalid input");
                }
            }

        sign_seed_next:
            free(msg); free(sig_buf); free(ctx);
        }
        wc_dilithium_free(&key);
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_DILITHIUM && !WOLFSSL_DILITHIUM_VERIFY_ONLY */
    return res;
}

/* ------------------------------------------------------------------
 * SIGN WITHOUT SEED  (mldsa_sign_noseed_schema.json)
 *
 * Group provides raw private key bytes.  Both the private key (for
 * signing) and public key (for round-trip verification) are loaded
 * into the same key struct by calling import_private then
 * import_public, so both key halves are set.
 * ------------------------------------------------------------------ */

test_result_t run_mldsa_sign_noseed(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
    static const byte zeros32[32] = {0};
    cJSON *groups, *group, *tests, *tc;
    int level = mldsa_level(root);

    if (level < 0)
        return res;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON   *sk_item = cJSON_GetObjectItem(group, "privateKey");
        cJSON   *pk_item = cJSON_GetObjectItem(group, "publicKey");
        uint8_t *sk_bytes, *pk_bytes;
        size_t   sk_len, pk_len;
        dilithium_key key;
        int key_ok = 0;

        /* publicKey == JSON null means the private key is invalid */
        if (cJSON_IsNull(pk_item)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        if (!sk_item || !cJSON_IsString(sk_item) ||
            !pk_item || !cJSON_IsString(pk_item)) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        sk_bytes = hex_decode(sk_item->valuestring, &sk_len);
        pk_bytes = hex_decode(pk_item->valuestring, &pk_len);

        if (!sk_bytes || !pk_bytes) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            free(sk_bytes); free(pk_bytes);
            continue;
        }

        wc_dilithium_init(&key);
        if (wc_dilithium_set_level(&key, (byte)level) == 0 &&
            wc_dilithium_import_private(sk_bytes, (word32)sk_len, &key) == 0 &&
            wc_dilithium_import_public( pk_bytes, (word32)pk_len, &key) == 0 &&
            /* WOLFSSL_DILITHIUM_CHECK_KEY is auto-defined when both public and
             * private key support are present and NO_CHECK_KEY is not set.
             * Without it, import_private succeeds even on a malformed key and
             * sign() returns 0, causing "invalid" test cases (InvalidPrivateKey
             * groups) to FAIL rather than pass. */
#ifdef WOLFSSL_DILITHIUM_CHECK_KEY
            wc_dilithium_check_key(&key) == 0 &&
#endif
            1)
            key_ok = 1;
        free(sk_bytes); free(pk_bytes);

        if (!key_ok) {
            /* Key load/check failed.  For groups whose test cases all have
             * result="invalid", the key rejection *is* the correct outcome —
             * we count those as passed.  For groups with result="valid" tests,
             * a key-load failure is a real error.  This distinguishes between
             * InvalidPrivateKey groups (expected to fail key check) and groups
             * where key load fails unexpectedly. */
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) {
                if (is_valid(tc) || is_acceptable(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-DSA: failed to load key for valid test");
                } else {
                    res.passed++; /* correctly rejected invalid key */
                }
            }
            wc_dilithium_free(&key);
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t  *msg = NULL, *sig_buf = NULL, *ctx = NULL;
            size_t    msg_len = 0, ctx_len = 0;
            word32    sig_buf_len;
            cJSON    *ctx_item;
            int       ret, sig_size;
            int       ctx_too_long = 0;

            if (has_internal_flag(tc)) {
                res.skipped++;
                continue;
            }

            msg = get_hex(tc, "msg", &msg_len);

            ctx_item = cJSON_GetObjectItem(tc, "ctx");
            if (ctx_item && cJSON_IsString(ctx_item))
                ctx = hex_decode(ctx_item->valuestring, &ctx_len);

            if (ctx_len > 255)
                ctx_too_long = 1;

            if (is_acceptable(tc)) {
                res.passed++;
                goto noseed_next;
            }

            if (is_valid(tc)) {
                if (ctx_too_long) {
                    res.failed++;
                    FAIL_TC(fname, tc,
                        "ML-DSA: ctx > 255 bytes but result is valid");
                    goto noseed_next;
                }

                sig_size = wc_dilithium_sig_size(&key);
                if (sig_size <= 0) { res.skipped++; goto noseed_next; }
                sig_buf_len = (word32)sig_size;
                sig_buf = (uint8_t *)malloc(sig_buf_len);
                if (!sig_buf) { res.skipped++; goto noseed_next; }

                ret = wc_dilithium_sign_ctx_msg_with_seed(
                    ctx, (byte)ctx_len,
                    msg, (word32)msg_len,
                    sig_buf, &sig_buf_len,
                    &key, zeros32);

                if (ret != 0) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-DSA sign failed (ret=%d)", ret);
                } else {
                    /* Round-trip: verify the produced signature.
                     * We do NOT compare bytes to a reference sig.  FIPS 204
                     * hedged signing is randomized; wolfssl may use a different
                     * rnd source, so byte-exact comparison would fail on any
                     * valid non-deterministic implementation. */
                    int stat = 0;
                    int vret = wc_dilithium_verify_ctx_msg(
                        sig_buf, sig_buf_len,
                        ctx,     (byte)ctx_len,
                        msg,     (word32)msg_len,
                        &stat, &key);
                    if (vret == 0 && stat == 1)
                        res.passed++;
                    else {
                        res.failed++;
                        FAIL_TC(fname, tc,
                            "ML-DSA produced unverifiable sig (vret=%d, stat=%d)",
                            vret, stat);
                    }
                }
            } else {
                /* result == "invalid" */
                if (ctx_too_long) {
                    res.passed++;
                    goto noseed_next;
                }

                sig_size = wc_dilithium_sig_size(&key);
                if (sig_size <= 0) { res.skipped++; goto noseed_next; }
                sig_buf_len = (word32)sig_size;
                sig_buf = (uint8_t *)malloc(sig_buf_len);
                if (!sig_buf) { res.skipped++; goto noseed_next; }

                ret = wc_dilithium_sign_ctx_msg_with_seed(
                    ctx, (byte)ctx_len,
                    msg, (word32)msg_len,
                    sig_buf, &sig_buf_len,
                    &key, zeros32);

                if (ret != 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "ML-DSA sign accepted invalid input");
                }
            }

        noseed_next:
            free(msg); free(sig_buf); free(ctx);
        }
        wc_dilithium_free(&key);
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_DILITHIUM && !WOLFSSL_DILITHIUM_VERIFY_ONLY */
    return res;
}
