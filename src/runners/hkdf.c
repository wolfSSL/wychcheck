#include "runner.h"
#include <wolfssl/wolfcrypt/kdf.h>

test_result_t run_hkdf(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef HAVE_HKDF
    cJSON *algo_item, *groups, *group, *tests, *tc;
    const char *algo;
    int hash_type = WC_HASH_TYPE_NONE;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item) { return res; }
    algo = algo_item->valuestring;
    if (strcmp(algo, "HKDF-SHA-1") == 0)   hash_type = WC_SHA;
    else if (strcmp(algo, "HKDF-SHA-256") == 0) hash_type = WC_SHA256;
    else if (strcmp(algo, "HKDF-SHA-384") == 0) hash_type = WC_SHA384;
    else if (strcmp(algo, "HKDF-SHA-512") == 0) hash_type = WC_SHA512;
    else { return res; }

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *ikm, *salt, *info, *okm;
            size_t ikm_len, salt_len, info_len, okm_len;
            cJSON *size_item;
            int size;
            uint8_t *out;
            int ret;

            ikm  = get_hex(tc, "ikm",  &ikm_len);
            salt = get_hex(tc, "salt", &salt_len);
            info = get_hex(tc, "info", &info_len);
            okm  = get_hex(tc, "okm",  &okm_len);
            size_item = cJSON_GetObjectItem(tc, "size");
            size = size_item ? size_item->valueint : (int)okm_len;

            out = malloc(size > 0 ? size : 1);

            ret = wc_HKDF(hash_type,
                          ikm, (word32)ikm_len,
                          salt, (word32)salt_len,
                          info, (word32)info_len,
                          out, (word32)size);

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0 && memcmp(out, okm, size) == 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "HKDF output mismatch"); }
            } else {
                /* invalid: expect wc_HKDF to fail or output to differ */
                if (ret != 0) res.passed++;
                else if (okm_len > 0 && memcmp(out, okm, size) != 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "HKDF accepted invalid"); }
            }

            free(ikm); free(salt); free(info); free(okm); free(out);
        }
    }
#else
    (void)root;
    (void)fname;
#endif
    return res;
}
