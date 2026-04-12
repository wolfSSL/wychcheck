#include "runner.h"

/*
 * Runner for Wycheproof RSASSA-PKCS1-v1_5 signature generation test vectors.
 *
 * Schema: rsassa_pkcs1_generate_schema_v1.json
 *
 * Each group supplies a private key (privateKeyPkcs8) and a hash algorithm
 * (sha).  Each test case supplies a message (msg) and the expected signature
 * (sig).  PKCS#1 v1.5 signing is deterministic, so generated signatures are
 * compared byte-for-byte against the expected value.
 *
 * wolfSSL API used:
 *   wc_SignatureGenerate()      — hash + DigestInfo-encode + RSA sign
 *   wc_GetPkcs8TraditionalOffset() + wc_RsaPrivateKeyDecode() — key import
 *
 * Feature guard: NO_RSA
 */

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/signature.h>
#endif

test_result_t run_rsa_sign(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_RSA
    cJSON *groups, *group, *tests, *tc;
    WC_RNG rng;
    int rng_ok = (wc_InitRng(&rng) == 0);

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *pkcs8_item = cJSON_GetObjectItem(group, "privateKeyPkcs8");
        cJSON *sha_item   = cJSON_GetObjectItem(group, "sha");
        uint8_t *pkcs8 = NULL;
        size_t pkcs8_len;
        RsaKey *key;
        int key_ok = 0, hash_type;

        if (!pkcs8_item || !sha_item) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        hash_type = wc_hash_type(sha_item->valuestring);
        if (hash_type == WC_HASH_TYPE_NONE) {
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
            uint8_t *msg = NULL, *exp_sig = NULL, *got_sig = NULL;
            size_t msg_len, exp_sig_len;
            word32 got_sig_len;
            int ret, key_size;

            msg     = get_hex(tc, "msg", &msg_len);
            exp_sig = get_hex(tc, "sig", &exp_sig_len);

            if (!exp_sig) {
                res.skipped++;
                free(msg); free(exp_sig);
                continue;
            }

            if (is_acceptable(tc)) {
                res.passed++;
                free(msg); free(exp_sig);
                continue;
            }

            key_size = wc_RsaEncryptSize(key);
            got_sig_len = (word32)(key_size > 0 ? key_size : 512);
            got_sig = (uint8_t *)malloc(got_sig_len);
            if (!got_sig) {
                res.skipped++;
                free(msg); free(exp_sig);
                continue;
            }

            /* wc_SignatureGenerate rejects data_len==0; hash manually first. */
            if (msg_len == 0) {
                byte hash_buf[WC_MAX_DIGEST_SIZE + 36];
                word32 h_len = (word32)wc_HashGetDigestSize(
                                   (enum wc_HashType)hash_type);
                word32 h_enc_len;
                int oid;
                ret = wc_Hash((enum wc_HashType)hash_type,
                              msg, 0, hash_buf, h_len);
                if (ret == 0) {
                    oid = wc_HashGetOID((enum wc_HashType)hash_type);
                    if (oid < 0) {
                        ret = oid;
                    } else {
                        h_enc_len = (word32)wc_EncodeSignature(
                                        hash_buf, hash_buf, h_len, oid);
                        ret = wc_SignatureGenerateHash(
                                  (enum wc_HashType)hash_type,
                                  WC_SIGNATURE_TYPE_RSA_W_ENC,
                                  hash_buf, h_enc_len,
                                  got_sig, &got_sig_len,
                                  key, sizeof(RsaKey),
                                  rng_ok ? &rng : NULL);
                    }
                }
            } else {
                ret = wc_SignatureGenerate(
                          (enum wc_HashType)hash_type,
                          WC_SIGNATURE_TYPE_RSA_W_ENC,
                          msg, (word32)msg_len,
                          got_sig, &got_sig_len,
                          key, sizeof(RsaKey),
                          rng_ok ? &rng : NULL);
            }

            if (is_valid(tc)) {
                if (ret == 0 && got_sig_len == exp_sig_len &&
                    memcmp(got_sig, exp_sig, exp_sig_len) == 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "RSA PKCS1 sign failed (%d)", ret);
                }
            } else {
                /* invalid: expect rejection */
                if (ret != 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "RSA PKCS1 sign accepted invalid input");
                }
            }

            free(msg); free(exp_sig); free(got_sig);
        }
        wc_FreeRsaKey(key);
        free(key);
    }

    if (rng_ok)
        wc_FreeRng(&rng);
#else
    (void)root;
    (void)fname;
#endif /* !NO_RSA */
    return res;
}
