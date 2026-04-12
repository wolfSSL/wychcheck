#include "runner.h"

/*
 * Runner for Wycheproof MAC-with-IV test vectors.
 *
 * Schema: mac_with_iv_test_schema_v1.json
 *
 * Currently handles: AES-GMAC (HAVE_AESGCM).
 * Other algorithms in this schema (e.g. VMAC) are not implemented in
 * wolfSSL and are skipped.
 *
 * Test format: key, iv, msg (data being authenticated), tag (expected MAC).
 * No ciphertext — this is MAC-only.
 *
 * Feature guard: HAVE_AESGCM
 */

#ifdef HAVE_AESGCM
#include <wolfssl/wolfcrypt/aes.h>
#endif

test_result_t run_mac_with_iv(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef HAVE_AESGCM
    cJSON *algo_item, *groups, *group, *tests, *tc;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item || !cJSON_IsString(algo_item) ||
        strcmp(algo_item->valuestring, "AES-GMAC") != 0)
        return res;  /* unsupported algorithm — not compiled in */

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *key = NULL, *iv = NULL, *msg = NULL, *tag = NULL;
            size_t key_len, iv_len, msg_len, tag_len;
            int ret;

            key = get_hex(tc, "key", &key_len);
            iv  = get_hex(tc, "iv",  &iv_len);
            msg = get_hex(tc, "msg", &msg_len);
            tag = get_hex(tc, "tag", &tag_len);

            if (!key || !iv || !tag) {
                res.skipped++;
                goto mac_iv_next;
            }

            ret = wc_GmacVerify(key, (word32)key_len,
                                iv,  (word32)iv_len,
                                msg, (word32)msg_len,
                                tag, (word32)tag_len);

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0) res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "AES-GMAC verify failed (%d)", ret);
                }
            } else {
                /* invalid: tag must not verify */
                if (ret != 0) res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "AES-GMAC accepted invalid tag");
                }
            }

        mac_iv_next:
            free(key); free(iv); free(msg); free(tag);
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* HAVE_AESGCM */
    return res;
}
