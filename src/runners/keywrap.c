#include "runner.h"
#include <wolfssl/wolfcrypt/aes.h>

test_result_t run_keywrap(const char *path)
{
    test_result_t res = {0, 0, 0};
#ifdef HAVE_AES_KEYWRAP
    cJSON *root, *groups, *group, *tests, *tc;
    const char *fname;

    root = load_json(path);
    if (!root) return res;

    fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;

    /* Only AES-WRAP is supported, not AES-KWP */
    {
        cJSON *algo = cJSON_GetObjectItem(root, "algorithm");
        if (!algo || strcmp(algo->valuestring, "AES-WRAP") != 0) {
            cJSON_Delete(root);
            return res;
        }
    }

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *key, *msg, *ct;
            size_t key_len, msg_len, ct_len;
            uint8_t out[512];
            int ret;

            key = get_hex(tc, "key", &key_len);
            msg = get_hex(tc, "msg", &msg_len);
            ct  = get_hex(tc, "ct",  &ct_len);

            ret = wc_AesKeyUnWrap(key, (word32)key_len,
                                  ct, (word32)ct_len,
                                  out, sizeof(out), NULL);

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret > 0 && (size_t)ret == msg_len &&
                    memcmp(out, msg, msg_len) == 0)
                    res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "keywrap unwrap failed (%d)", ret); }
            } else {
                if (ret <= 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "keywrap accepted invalid"); }
            }

            free(key); free(msg); free(ct);
        }
    }
    cJSON_Delete(root);
#else
    (void)path;
#endif
    return res;
}
