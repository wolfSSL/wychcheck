#include "runner.h"

/*
 * Runner for Wycheproof PBKDF2 test vectors (pbkdf_test_schema.json).
 *
 * Each file covers one HMAC variant determined by the root "algorithm"
 * field ("PBKDF2-HMACSHA256" etc.).  All test cases are "valid"; each
 * provides password, salt, iterationCount, dkLen, and expected dk.
 *
 * Feature guard: !NO_PWDBASED
 */

#ifndef NO_PWDBASED
#include <wolfssl/wolfcrypt/pwdbased.h>

/* Map PBKDF2 algorithm name to wolfssl hash type constant.
 * Returns WC_HASH_TYPE_NONE for unrecognised algorithms. */
static int pbkdf2_hash_type(const char *algo)
{
    if (!algo) return WC_HASH_TYPE_NONE;
    if (strcmp(algo, "PBKDF2-HMACSHA1")   == 0) return WC_HASH_TYPE_SHA;
    if (strcmp(algo, "PBKDF2-HMACSHA224") == 0) return WC_HASH_TYPE_SHA224;
    if (strcmp(algo, "PBKDF2-HMACSHA256") == 0) return WC_HASH_TYPE_SHA256;
    if (strcmp(algo, "PBKDF2-HMACSHA384") == 0) return WC_HASH_TYPE_SHA384;
    if (strcmp(algo, "PBKDF2-HMACSHA512") == 0) return WC_HASH_TYPE_SHA512;
    return WC_HASH_TYPE_NONE;
}
#endif /* !NO_PWDBASED */


test_result_t run_pbkdf2(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_PWDBASED
    cJSON *algo_item, *groups, *group, *tests, *tc;
    const char *algo;
    int hash_type;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item || !cJSON_IsString(algo_item)) return res;
    algo = algo_item->valuestring;

    hash_type = pbkdf2_hash_type(algo);
    if (hash_type == WC_HASH_TYPE_NONE) return res;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *password = NULL, *salt = NULL, *exp_dk = NULL;
            size_t   password_len, salt_len, exp_dk_len;
            cJSON   *dk_len_item, *icount_item;
            int      dk_len, iter_count, ret;
            uint8_t *got_dk = NULL;

            password = get_hex(tc, "password", &password_len);
            salt     = get_hex(tc, "salt",     &salt_len);
            exp_dk   = get_hex(tc, "dk",       &exp_dk_len);

            dk_len_item = cJSON_GetObjectItem(tc, "dkLen");
            icount_item = cJSON_GetObjectItem(tc, "iterationCount");

            if (!password || !salt || !exp_dk ||
                !dk_len_item || !cJSON_IsNumber(dk_len_item) ||
                !icount_item || !cJSON_IsNumber(icount_item)) {
                res.skipped++;
                goto pbkdf2_next;
            }

            dk_len     = dk_len_item->valueint;
            iter_count = icount_item->valueint;

            if (dk_len <= 0 || (size_t)dk_len != exp_dk_len) {
                res.skipped++;
                goto pbkdf2_next;
            }

            got_dk = (uint8_t *)malloc((size_t)dk_len);
            if (!got_dk) { res.skipped++; goto pbkdf2_next; }

            ret = wc_PBKDF2(got_dk,
                            password, (int)password_len,
                            salt,     (int)salt_len,
                            iter_count, dk_len, hash_type);

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "PBKDF2 failed (%d)", ret);
            } else if (memcmp(got_dk, exp_dk, (size_t)dk_len) != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "PBKDF2 dk mismatch");
            } else {
                res.passed++;
            }

        pbkdf2_next:
            free(password); free(salt); free(exp_dk); free(got_dk);
        }
    }
#else
    (void)root; (void)fname;
#endif /* !NO_PWDBASED */
    return res;
}
