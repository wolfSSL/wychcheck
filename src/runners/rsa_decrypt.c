#include "runner.h"

/*
 * Runner for Wycheproof RSAES-PKCS1-v1_5 decryption test vectors.
 *
 * Schema: rsaes_pkcs1_decrypt_schema_v1.json
 *
 * The private key is provided as a PKCS#8 DER blob ("privateKeyPkcs8"
 * group field).  Each test case supplies a ciphertext ("ct") and the
 * expected plaintext ("msg").  Valid tests must decrypt correctly;
 * invalid tests must return a decryption error (padding failure).
 *
 * wolfSSL API used:
 *   wc_RsaPrivateDecrypt()  — PKCS#1 v1.5 decrypt (deterministic)
 *   wc_GetPkcs8TraditionalOffset() + wc_RsaPrivateKeyDecode() — key import
 *
 * Feature guard: NO_RSA.  wolfSSL must be built without NO_RSA.
 */

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

test_result_t run_rsa_decrypt(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_RSA
    cJSON *groups, *group, *tests, *tc;
    WC_RNG rng;

    /* RNG is needed when wolfSSL uses RSA blinding (constant-time
     * exponentiation).  If InitRng fails we still attempt decryption
     * without blinding — wc_RsaSetRNG is advisory, not mandatory. */
    int rng_ok = (wc_InitRng(&rng) == 0);

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *pkcs8_item = cJSON_GetObjectItem(group, "privateKeyPkcs8");
        uint8_t *pkcs8;
        size_t pkcs8_len;
        RsaKey *key;
        int key_ok = 0;

        if (!pkcs8_item) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        pkcs8 = hex_decode(pkcs8_item->valuestring, &pkcs8_len);
        if (!pkcs8) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        key = (RsaKey *)malloc(sizeof(RsaKey));
        if (!key) { free(pkcs8); continue; }

        wc_InitRsaKey(key, NULL);
        if (rng_ok)
            wc_RsaSetRNG(key, &rng);

        {
            word32 idx = 0;
            int trad_off = wc_GetPkcs8TraditionalOffset(pkcs8, &idx,
                                                         (word32)pkcs8_len);
            if (trad_off >= 0) {
                word32 rsa_idx = idx;
                if (wc_RsaPrivateKeyDecode(pkcs8, &rsa_idx, key,
                                           (word32)pkcs8_len) == 0)
                    key_ok = 1;
            }
        }
        free(pkcs8);

        /* Skip groups whose key exceeds the compiled-in RSA_MAX_SIZE limit. */
        if (!key_ok
#ifdef RSA_MAX_SIZE
            || (wc_RsaEncryptSize(key) * 8 > RSA_MAX_SIZE)
#endif
        ) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            wc_FreeRsaKey(key);
            free(key);
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *ct_bytes, *msg_exp;
            size_t ct_len, msg_len;
            uint8_t *dec_buf;
            int ret, key_size;

            ct_bytes = get_hex(tc, "ct",  &ct_len);
            msg_exp  = get_hex(tc, "msg", &msg_len);

            if (!ct_bytes) {
                res.skipped++;
                free(ct_bytes); free(msg_exp);
                continue;
            }

#ifndef WOLFSSL_RSA_DECRYPT_TO_0_LEN
            /* wolfSSL returns RSA_BUFFER_E instead of 0 for zero-length
             * plaintext unless compiled with WOLFSSL_RSA_DECRYPT_TO_0_LEN.
             * Skip these test cases rather than reporting false failures. */
            if (is_valid(tc) && msg_len == 0) {
                res.skipped++;
                free(ct_bytes); free(msg_exp);
                continue;
            }
#endif

            key_size = wc_RsaEncryptSize(key);
            dec_buf = (uint8_t *)malloc(key_size > 0 ? key_size : 512);

            if (dec_buf) {
                ret = wc_RsaPrivateDecrypt(ct_bytes, (word32)ct_len,
                                           dec_buf, (word32)key_size, key);
            } else {
                ret = -1;
            }

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                /* Decrypted plaintext must match expected message exactly. */
                if (ret >= 0 && (size_t)ret == msg_len &&
                    (msg_len == 0 || memcmp(dec_buf, msg_exp, msg_len) == 0))
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "RSA PKCS1 decrypt failed (%d)", ret);
                }
            } else {
                /* invalid: decryption must fail with a padding error */
                if (ret < 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "RSA PKCS1 accepted invalid ciphertext");
                }
            }

            free(ct_bytes); free(msg_exp); free(dec_buf);
        }
        wc_FreeRsaKey(key);
        free(key);
    }

    if (rng_ok)
        wc_FreeRng(&rng);
#else
    (void)root;
    (void)fname;
#endif
    return res;
}
