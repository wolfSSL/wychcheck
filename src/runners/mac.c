#include "runner.h"
#include <wolfssl/wolfcrypt/hmac.h>
#ifdef WOLFSSL_CMAC
#include <wolfssl/wolfcrypt/cmac.h>
#endif
#ifdef WOLFSSL_SIPHASH
#include <wolfssl/wolfcrypt/siphash.h>
#endif

static int hmac_type_from_algo(const char *algo)
{
    if (strcmp(algo, "HMACSHA1") == 0)   return WC_SHA;
#ifndef NO_SHA256
    if (strcmp(algo, "HMACSHA224") == 0) return WC_SHA224;
    if (strcmp(algo, "HMACSHA256") == 0) return WC_SHA256;
#endif
#ifdef WOLFSSL_SHA384
    if (strcmp(algo, "HMACSHA384") == 0) return WC_SHA384;
#endif
#ifdef WOLFSSL_SHA512
    if (strcmp(algo, "HMACSHA512") == 0) return WC_SHA512;
#endif
#ifdef WOLFSSL_SHA3
    if (strcmp(algo, "HMACSHA3-224") == 0) return WC_SHA3_224;
    if (strcmp(algo, "HMACSHA3-256") == 0) return WC_SHA3_256;
    if (strcmp(algo, "HMACSHA3-384") == 0) return WC_SHA3_384;
    if (strcmp(algo, "HMACSHA3-512") == 0) return WC_SHA3_512;
#endif
    return -1;
}

test_result_t run_mac(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
    cJSON *algo_item, *groups, *group, *tests, *tc;
    const char *algo;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item || !cJSON_IsString(algo_item)) { return res; }
    algo = algo_item->valuestring;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *tag_size_item = cJSON_GetObjectItem(group, "tagSize");
        int tag_bits = tag_size_item ? tag_size_item->valueint : 0;
        int tag_bytes = tag_bits / 8;

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *key, *msg, *exp_tag;
            size_t key_len, msg_len, exp_tag_len;
            int match = 0;

            key     = get_hex(tc, "key", &key_len);
            msg     = get_hex(tc, "msg", &msg_len);
            exp_tag = get_hex(tc, "tag", &exp_tag_len);

            if (strncmp(algo, "HMAC", 4) == 0) {
                int htype = hmac_type_from_algo(algo);
                if (htype < 0) {
                    res.skipped++;
                    goto next;
                }
#ifndef NO_HMAC
                {
                    Hmac hmac;
                    uint8_t out[WC_MAX_DIGEST_SIZE];
                    int ret;

                    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
                    if (ret != 0) { res.skipped++; goto next; }
                    ret = wc_HmacSetKey(&hmac, htype, key, (word32)key_len);
                    if (ret != 0) { wc_HmacFree(&hmac); res.skipped++; goto next; }
                    ret = wc_HmacUpdate(&hmac, msg, (word32)msg_len);
                    if (ret == 0) ret = wc_HmacFinal(&hmac, out);
                    wc_HmacFree(&hmac);

                    if (ret == 0 && (int)exp_tag_len >= tag_bytes)
                        match = (memcmp(out, exp_tag, tag_bytes) == 0);
                }
#else
                res.skipped++;
                goto next;
#endif
            }
#ifdef WOLFSSL_CMAC
            else if (strcmp(algo, "AES-CMAC") == 0) {
                uint8_t out[WC_AES_BLOCK_SIZE];
                word32 out_len = sizeof(out);
                int ret = wc_AesCmacGenerate(out, &out_len,
                                             msg, (word32)msg_len,
                                             key, (word32)key_len);
                if (ret == 0 && (int)out_len >= tag_bytes)
                    match = (memcmp(out, exp_tag, tag_bytes) == 0);
            }
#endif
#ifdef WOLFSSL_SIPHASH
            else if (strncmp(algo, "SIPHASH", 7) == 0) {
                uint8_t out[16];
                int ret;
                word32 out_sz = (word32)tag_bytes;

                if (out_sz != 8 && out_sz != 16) {
                    res.skipped++;
                    goto next;
                }
                ret = wc_SipHash(key, msg, (word32)msg_len, out, out_sz);
                if (ret == 0)
                    match = (memcmp(out, exp_tag, tag_bytes) == 0);
            }
#endif
            else {
                res.skipped++;
                goto next;
            }

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (match) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "%s tag mismatch", algo); }
            } else {
                if (!match) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "%s accepted invalid tag", algo); }
            }
        next:
            free(key); free(msg); free(exp_tag);
        }
    }

    return res;
}
