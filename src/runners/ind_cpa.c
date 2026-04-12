#include "runner.h"
#include <wolfssl/wolfcrypt/aes.h>

/* AES-CBC-PKCS5: wolfcrypt does raw CBC, we must check PKCS5 padding ourselves */
#ifdef HAVE_AES_CBC
static int test_aes_cbc_pkcs5(const uint8_t *key, size_t key_len,
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t *msg, size_t msg_len)
{
    Aes aes;
    uint8_t *out;
    int ret, pad, i;

    (void)iv_len;
    if (ct_len == 0 || ct_len % WC_AES_BLOCK_SIZE != 0)
        return -1;

    out = malloc(ct_len);
    if (!out) return -1;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(out); return ret; }

    ret = wc_AesSetKey(&aes, key, (word32)key_len, iv, AES_DECRYPTION);
    if (ret != 0) { wc_AesFree(&aes); free(out); return ret; }

    ret = wc_AesCbcDecrypt(&aes, out, ct, (word32)ct_len);
    wc_AesFree(&aes);
    if (ret != 0) { free(out); return ret; }

    /* verify and strip PKCS5 padding */
    pad = out[ct_len - 1];
    if (pad < 1 || pad > WC_AES_BLOCK_SIZE) { free(out); return -1; }
    for (i = 0; i < pad; i++) {
        if (out[ct_len - 1 - i] != pad) { free(out); return -1; }
    }

    /* compare unpadded plaintext */
    if (ct_len - pad != msg_len || memcmp(out, msg, msg_len) != 0)
        ret = -1;

    free(out);
    return ret;
}
#endif

#ifdef WOLFSSL_AES_XTS
static int test_aes_xts(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *msg, size_t msg_len)
{
    XtsAes xts;
    uint8_t *out;
    uint8_t tweak[WC_AES_BLOCK_SIZE];
    int ret;

    /* XTS key is split: half for AES, half for tweak cipher */
    if (ct_len == 0) return -1;

    out = malloc(ct_len);
    if (!out) return -1;

    /* iv in wycheproof XTS is the tweak, may be shorter than 16 bytes */
    memset(tweak, 0, sizeof(tweak));
    if (iv_len > sizeof(tweak)) iv_len = sizeof(tweak);
    memcpy(tweak, iv, iv_len);

    ret = wc_AesXtsInit(&xts, NULL, INVALID_DEVID);
    if (ret != 0) { free(out); return ret; }

    ret = wc_AesXtsSetKeyNoInit(&xts, key, (word32)key_len, AES_DECRYPTION);
    if (ret != 0) { wc_AesXtsFree(&xts); free(out); return ret; }

    ret = wc_AesXtsDecrypt(&xts, out, ct, (word32)ct_len, tweak, WC_AES_BLOCK_SIZE);
    wc_AesXtsFree(&xts);
    if (ret != 0) { free(out); return ret; }

    if (ct_len != msg_len || memcmp(out, msg, msg_len) != 0)
        ret = -1;

    free(out);
    return ret;
}
#endif

test_result_t run_ind_cpa(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
    cJSON *algo_item, *groups, *group, *tests, *tc;
    const char *algo;
    int is_cbc = 0, is_xts = 0;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item) { return res; }
    algo = algo_item->valuestring;

    if (strcmp(algo, "AES-CBC-PKCS5") == 0) is_cbc = 1;
    else if (strcmp(algo, "AES-XTS") == 0) is_xts = 1;
    else { return res; }

#ifndef HAVE_AES_CBC
    if (is_cbc) { return res; }
#endif
#ifndef WOLFSSL_AES_XTS
    if (is_xts) { return res; }
#endif

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *key, *iv, *ct, *msg;
            size_t key_len, iv_len, ct_len, msg_len;
            int ret = -1;

            key = get_hex(tc, "key", &key_len);
            iv  = get_hex(tc, "iv",  &iv_len);
            ct  = get_hex(tc, "ct",  &ct_len);
            msg = get_hex(tc, "msg", &msg_len);

#ifdef HAVE_AES_CBC
            if (is_cbc)
                ret = test_aes_cbc_pkcs5(key, key_len, iv, iv_len,
                                         ct, ct_len, msg, msg_len);
#endif
#ifdef WOLFSSL_AES_XTS
            if (is_xts)
                ret = test_aes_xts(key, key_len, iv, iv_len,
                                   ct, ct_len, msg, msg_len);
#endif

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "%s decrypt failed (%d)", algo, ret); }
            } else {
                if (ret != 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "%s accepted invalid", algo); }
            }

            free(key); free(iv); free(ct); free(msg);
        }
    }

    return res;
}
