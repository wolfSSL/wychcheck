#include "runner.h"
#include <wolfssl/wolfcrypt/aes.h>

/*
 * Runner for Wycheproof PBES2 test vectors (pbe_test_schema.json).
 *
 * PBES2 = PBKDF2 key derivation + AES-CBC decryption with PKCS7 padding.
 * Each file covers one (HMAC, AES key size) combination encoded in the
 * root "algorithm" field ("PbeWithHmacSha256AndAes_128" etc.).
 * All test cases are "valid".
 *
 * Fields per test case: password, salt, iterationCount, iv, ct, msg.
 *
 * Feature guards: !NO_PWDBASED && HAVE_AES_CBC
 */

#if !defined(NO_PWDBASED) && defined(HAVE_AES_CBC)
#include <wolfssl/wolfcrypt/pwdbased.h>

/* Parse PBES2 algorithm string to (hash type, AES key bytes).
 * Format: "PbeWithHmacSha{N}AndAes_{K}"
 * Returns 0 on success, -1 if unrecognised. */
static int pbes2_params(const char *algo, int *hash_type_out, int *key_len_out)
{
    int hash_type, key_len;

    if (!algo) return -1;

    if      (strstr(algo, "Sha512") != NULL) hash_type = WC_HASH_TYPE_SHA512;
    else if (strstr(algo, "Sha384") != NULL) hash_type = WC_HASH_TYPE_SHA384;
    else if (strstr(algo, "Sha256") != NULL) hash_type = WC_HASH_TYPE_SHA256;
    else if (strstr(algo, "Sha224") != NULL) hash_type = WC_HASH_TYPE_SHA224;
    else if (strstr(algo, "Sha1")   != NULL) hash_type = WC_HASH_TYPE_SHA;
    else return -1;

    if      (strstr(algo, "Aes_128") != NULL) key_len = 16;
    else if (strstr(algo, "Aes_192") != NULL) key_len = 24;
    else if (strstr(algo, "Aes_256") != NULL) key_len = 32;
    else return -1;

    *hash_type_out = hash_type;
    *key_len_out   = key_len;
    return 0;
}

/* AES-CBC decrypt then verify PKCS7 padding and compare to expected msg.
 * Returns 0 if decryption succeeds and plaintext matches exp_msg. */
static int pbes2_decrypt_cmp(
    const uint8_t *key, int key_len,
    const uint8_t *iv,
    const uint8_t *ct, size_t ct_len,
    const uint8_t *exp_msg, size_t exp_msg_len)
{
    Aes      aes;
    uint8_t *out;
    int      ret, pad, i;

    if (ct_len == 0 || ct_len % WC_AES_BLOCK_SIZE != 0)
        return -1;

    out = (uint8_t *)malloc(ct_len);
    if (!out) return -1;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(out); return ret; }

    ret = wc_AesSetKey(&aes, key, (word32)key_len, iv, AES_DECRYPTION);
    if (ret != 0) { wc_AesFree(&aes); free(out); return ret; }

    ret = wc_AesCbcDecrypt(&aes, out, ct, (word32)ct_len);
    wc_AesFree(&aes);
    if (ret != 0) { free(out); return ret; }

    /* Verify and strip PKCS7 padding */
    pad = (int)(uint8_t)out[ct_len - 1];
    if (pad < 1 || pad > WC_AES_BLOCK_SIZE) { free(out); return -1; }
    for (i = 0; i < pad; i++) {
        if (out[ct_len - 1 - (size_t)i] != (uint8_t)pad) {
            free(out);
            return -1;
        }
    }

    /* Compare unpadded plaintext to expected msg */
    if (ct_len - (size_t)pad != exp_msg_len ||
        (exp_msg_len > 0 && memcmp(out, exp_msg, exp_msg_len) != 0))
        ret = -1;

    free(out);
    return ret;
}
#endif /* !NO_PWDBASED && HAVE_AES_CBC */


test_result_t run_pbes2(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if !defined(NO_PWDBASED) && defined(HAVE_AES_CBC)
    cJSON *algo_item, *groups, *group, *tests, *tc;
    const char *algo;
    int hash_type, key_len;

    algo_item = cJSON_GetObjectItem(root, "algorithm");
    if (!algo_item || !cJSON_IsString(algo_item)) return res;
    algo = algo_item->valuestring;

    if (pbes2_params(algo, &hash_type, &key_len) != 0) return res;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *password = NULL, *salt = NULL, *iv = NULL;
            uint8_t *ct = NULL, *exp_msg = NULL;
            size_t   password_len, salt_len, iv_len, ct_len, exp_msg_len;
            cJSON   *icount_item;
            int      iter_count, ret;
            uint8_t  derived_key[32]; /* max 256-bit AES key */

            password = get_hex(tc, "password", &password_len);
            salt     = get_hex(tc, "salt",     &salt_len);
            iv       = get_hex(tc, "iv",       &iv_len);
            ct       = get_hex(tc, "ct",       &ct_len);
            exp_msg  = get_hex(tc, "msg",      &exp_msg_len);
            icount_item = cJSON_GetObjectItem(tc, "iterationCount");

            if (!password || !salt || !iv || !ct ||
                !icount_item || !cJSON_IsNumber(icount_item) ||
                iv_len != WC_AES_BLOCK_SIZE) {
                res.skipped++;
                goto pbes2_next;
            }

            iter_count = icount_item->valueint;

            ret = wc_PBKDF2(derived_key,
                            password, (int)password_len,
                            salt,     (int)salt_len,
                            iter_count, key_len, hash_type);
            if (ret != 0) {
                res.skipped++;
                goto pbes2_next;
            }

            ret = pbes2_decrypt_cmp(derived_key, key_len,
                                    iv, ct, ct_len,
                                    exp_msg, exp_msg_len);

            if (ret != 0) {
                res.failed++;
                FAIL_TC(fname, tc, "PBES2 decrypt/compare failed (%d)", ret);
            } else {
                res.passed++;
            }

        pbes2_next:
            free(password); free(salt); free(iv); free(ct); free(exp_msg);
        }
    }
#else
    (void)root; (void)fname;
#endif /* !NO_PWDBASED && HAVE_AES_CBC */
    return res;
}
