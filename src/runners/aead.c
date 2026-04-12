#include "runner.h"
#include <wolfssl/wolfcrypt/aes.h>
#ifdef HAVE_CHACHA
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif

/* Determine which AEAD backend to call based on the algorithm string */

#ifdef HAVE_AESGCM
static int test_aes_gcm(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *tag, size_t tag_len,
                        const uint8_t *msg, size_t msg_len)
{
    Aes aes;
    uint8_t *out = NULL;
    int ret;

    if (msg_len > 0) {
        out = malloc(msg_len);
        if (!out) return -1;
    }

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(out); return ret; }

    ret = wc_AesGcmSetKey(&aes, key, (word32)key_len);
    if (ret != 0) { wc_AesFree(&aes); free(out); return ret; }

    ret = wc_AesGcmDecrypt(&aes, out, ct, (word32)ct_len,
                           iv, (word32)iv_len,
                           tag, (word32)tag_len,
                           aad, (word32)aad_len);
    wc_AesFree(&aes);

    if (ret == 0 && msg_len > 0 && memcmp(out, msg, msg_len) != 0)
        ret = -1;
    free(out);
    return ret;
}
#endif

#ifdef HAVE_AESCCM
static int test_aes_ccm(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *tag, size_t tag_len,
                        const uint8_t *msg, size_t msg_len)
{
    Aes aes;
    uint8_t *out = NULL;
    int ret;

    if (msg_len > 0) {
        out = malloc(msg_len);
        if (!out) return -1;
    }

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(out); return ret; }

    ret = wc_AesCcmSetKey(&aes, key, (word32)key_len);
    if (ret != 0) { wc_AesFree(&aes); free(out); return ret; }

    ret = wc_AesCcmDecrypt(&aes, out, ct, (word32)ct_len,
                           iv, (word32)iv_len,
                           tag, (word32)tag_len,
                           aad, (word32)aad_len);
    wc_AesFree(&aes);

    if (ret == 0 && msg_len > 0 && memcmp(out, msg, msg_len) != 0)
        ret = -1;
    free(out);
    return ret;
}
#endif

#ifdef WOLFSSL_AES_EAX
static int test_aes_eax(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *tag, size_t tag_len,
                        const uint8_t *msg, size_t msg_len)
{
    uint8_t *out = NULL;
    uint8_t verify_tag[WC_AES_BLOCK_SIZE];
    int ret;

    if (msg_len > 0) {
        out = malloc(msg_len);
        if (!out) return -1;
    }

    if (tag_len > WC_AES_BLOCK_SIZE) { free(out); return -1; }
    memcpy(verify_tag, tag, tag_len);

    ret = wc_AesEaxDecryptAuth(key, (word32)key_len,
                               out, ct, (word32)ct_len,
                               iv, (word32)iv_len,
                               verify_tag, (word32)tag_len,
                               aad, (word32)aad_len);

    if (ret == 0 && msg_len > 0 && memcmp(out, msg, msg_len) != 0)
        ret = -1;
    free(out);
    return ret;
}
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
static int test_chacha_poly(const uint8_t *key, size_t key_len,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t *tag, size_t tag_len,
                            const uint8_t *msg, size_t msg_len)
{
    uint8_t *out = NULL;
    int ret;

    (void)key_len;
    if (iv_len != CHACHA20_POLY1305_AEAD_IV_SIZE) return -1;
    if (tag_len != CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) return -1;

    if (msg_len > 0) {
        out = malloc(msg_len);
        if (!out) return -1;
    }
    ret = wc_ChaCha20Poly1305_Decrypt(key, iv, aad, (word32)aad_len,
                                      ct, (word32)ct_len,
                                      tag, out);
    if (ret == 0 && msg_len > 0 && memcmp(out, msg, msg_len) != 0)
        ret = -1;
    free(out);
    return ret;
}
#endif

#ifdef HAVE_XCHACHA
static int test_xchacha_poly(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t *tag, size_t tag_len,
                             const uint8_t *msg, size_t msg_len)
{
    uint8_t *out = NULL;
    uint8_t *src = NULL;
    size_t src_len;
    int ret;

    /* XChaCha API wants ct||tag concatenated as src */
    src_len = ct_len + tag_len;
    src = malloc(src_len > 0 ? src_len : 1);
    if (!src) return -1;
    if (ct_len > 0) memcpy(src, ct, ct_len);
    memcpy(src + ct_len, tag, tag_len);

    if (msg_len > 0) {
        out = malloc(msg_len);
        if (!out) { free(src); return -1; }
    }

    ret = wc_XChaCha20Poly1305_Decrypt(out, msg_len,
                                       src, src_len,
                                       aad, aad_len,
                                       iv, iv_len,
                                       key, key_len);
    if (ret == 0 && msg_len > 0 && memcmp(out, msg, msg_len) != 0)
        ret = -1;
    free(out);
    free(src);
    return ret;
}
#endif

typedef int (*aead_fn)(const uint8_t *key, size_t key_len,
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       const uint8_t *msg, size_t msg_len);

static aead_fn pick_aead(const char *algo)
{
#ifdef HAVE_AESGCM
    if (strcmp(algo, "AES-GCM") == 0) return test_aes_gcm;
#endif
#ifdef HAVE_AESCCM
    if (strcmp(algo, "AES-CCM") == 0) return test_aes_ccm;
#endif
#ifdef WOLFSSL_AES_EAX
    if (strcmp(algo, "AES-EAX") == 0) return test_aes_eax;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (strcmp(algo, "CHACHA20-POLY1305") == 0) return test_chacha_poly;
#endif
#ifdef HAVE_XCHACHA
    if (strcmp(algo, "XCHACHA20-POLY1305") == 0) return test_xchacha_poly;
#endif
    (void)algo;
    return NULL;
}

test_result_t run_aead(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
    cJSON *algo_item, *groups, *group, *tests, *tc;
    aead_fn fn;
    const char *algo;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item || !cJSON_IsString(algo_item)) {
        return res;
    }
    algo = algo_item->valuestring;
    fn = pick_aead(algo);
    if (!fn) {
        /* algorithm not compiled in */
        return res;
    }

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *key, *iv, *aad, *msg, *ct, *tag;
            size_t key_len, iv_len, aad_len, msg_len, ct_len, tag_len;
            int ret;

            key = get_hex(tc, "key", &key_len);
            iv  = get_hex(tc, "iv",  &iv_len);
            aad = get_hex(tc, "aad", &aad_len);
            msg = get_hex(tc, "msg", &msg_len);
            ct  = get_hex(tc, "ct",  &ct_len);
            tag = get_hex(tc, "tag", &tag_len);

            ret = fn(key, key_len, iv, iv_len, aad, aad_len,
                     ct, ct_len, tag, tag_len, msg, msg_len);

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "%s decrypt valid vector failed (%d)", algo, ret); }
            } else {
                if (ret != 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "%s accepted invalid vector", algo); }
            }

            free(key); free(iv); free(aad); free(msg); free(ct); free(tag);
        }
    }

    return res;
}
