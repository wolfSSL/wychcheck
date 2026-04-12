#include "runner.h"

/*
 * Runner for Wycheproof Deterministic AEAD test vectors.
 *
 * Schema: daead_test_schema_v1.json
 * Algorithm: AES-SIV-CMAC (RFC 5297)
 *
 * Unlike the AEAD schema, DAEAD has no separate nonce field — the SIV
 * is computed deterministically from the key, AAD, and plaintext.
 *
 * Wire format: "ct" = SIV (16 bytes) || ciphertext body
 * No separate "tag" or "iv" fields.
 *
 * Feature guard: WOLFSSL_AES_SIV
 */

#ifdef WOLFSSL_AES_SIV
#include <wolfssl/wolfcrypt/aes.h>

#define DAEAD_SIV_SZ 16
#endif

test_result_t run_daead(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifdef WOLFSSL_AES_SIV
    cJSON *algo_item, *groups, *group, *tests, *tc;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item || !cJSON_IsString(algo_item) ||
        strcmp(algo_item->valuestring, "AES-SIV-CMAC") != 0)
        return res;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *key = NULL, *aad = NULL, *msg = NULL, *ct_full = NULL;
            size_t key_len, aad_len, msg_len, ct_full_len;
            uint8_t *out = NULL;
            byte siv[DAEAD_SIV_SZ];
            const uint8_t *ct_body;
            size_t ct_body_len;
            int ret;

            key     = get_hex(tc, "key", &key_len);
            aad     = get_hex(tc, "aad", &aad_len);
            msg     = get_hex(tc, "msg", &msg_len);
            ct_full = get_hex(tc, "ct",  &ct_full_len);

            if (!key || !ct_full || ct_full_len < DAEAD_SIV_SZ) {
                res.skipped++;
                goto daead_next;
            }

            /* ct = SIV (16 bytes) || ciphertext body */
            memcpy(siv, ct_full, DAEAD_SIV_SZ);
            ct_body     = ct_full + DAEAD_SIV_SZ;
            ct_body_len = ct_full_len - DAEAD_SIV_SZ;

            /* wc_AesSivDecrypt rejects NULL out even when dataSz==0 */
            out = malloc(ct_body_len > 0 ? ct_body_len : 1);
            if (!out) { res.skipped++; goto daead_next; }

            /* No nonce/IV: pure deterministic mode */
            ret = wc_AesSivDecrypt(key, (word32)key_len,
                                   aad, (word32)aad_len,
                                   NULL, 0,
                                   ct_body, (word32)ct_body_len,
                                   siv, out);

            if (is_valid(tc)) {
                if (ret == 0 && msg_len == ct_body_len &&
                    (ct_body_len == 0 || memcmp(out, msg, msg_len) == 0))
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "AES-SIV-CMAC decrypt failed (%d)", ret);
                }
            } else {
                /* invalid: authentication must fail */
                if (ret != 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "AES-SIV-CMAC accepted invalid ciphertext");
                }
            }

        daead_next:
            free(key); free(aad); free(msg); free(ct_full); free(out);
            out = NULL;
        }
    }
#else
    (void)root;
    (void)fname;
#endif /* WOLFSSL_AES_SIV */
    return res;
}
