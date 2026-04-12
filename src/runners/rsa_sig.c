#include "runner.h"

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#endif

test_result_t run_rsa_sig(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_RSA
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *der_item = cJSON_GetObjectItem(group, "publicKeyDer");
        cJSON *sha_item = cJSON_GetObjectItem(group, "sha");
        uint8_t *pub_der;
        size_t pub_der_len;
        int hash_type, hash_len;
        RsaKey *key;
        int key_ok = 0;

        if (!der_item || !sha_item) continue;

        pub_der = hex_decode(der_item->valuestring, &pub_der_len);
        hash_type = wc_hash_type(sha_item->valuestring);
        hash_len = wc_HashGetDigestSize((enum wc_HashType)hash_type);

        if (hash_type == WC_HASH_TYPE_NONE || hash_len <= 0 || !pub_der) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            free(pub_der);
            continue;
        }

        key = (RsaKey *)malloc(sizeof(RsaKey));
        if (!key) { free(pub_der); continue; }

        wc_InitRsaKey(key, NULL);
        {
            word32 idx = 0;
            if (wc_RsaPublicKeyDecode(pub_der, &idx, key,
                                      (word32)pub_der_len) == 0)
                key_ok = 1;
        }
        free(pub_der);

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
            uint8_t *msg_bytes, *sig_bytes;
            size_t msg_len, sig_len;
            int ret;

            msg_bytes = get_hex(tc, "msg", &msg_len);
            sig_bytes = get_hex(tc, "sig", &sig_len);

            /* wc_SignatureVerify rejects data_len==0 (empty message),
               so hash manually and use wc_SignatureVerifyHash instead. */
            if (msg_len == 0) {
                byte hash_buf[WC_MAX_DIGEST_SIZE + 36]; /* room for DER prefix */
                word32 h_len = (word32)hash_len;
                word32 h_enc_len;
                int oid;

                ret = wc_Hash((enum wc_HashType)hash_type,
                              msg_bytes, 0, hash_buf, h_len);
                if (ret == 0) {
                    oid = wc_HashGetOID((enum wc_HashType)hash_type);
                    if (oid < 0) { ret = oid; }
                    else {
                        h_enc_len = (word32)wc_EncodeSignature(
                                        hash_buf, hash_buf, h_len, oid);
                        ret = wc_SignatureVerifyHash(
                                  (enum wc_HashType)hash_type,
                                  WC_SIGNATURE_TYPE_RSA_W_ENC,
                                  hash_buf, h_enc_len,
                                  sig_bytes, (word32)sig_len,
                                  key, sizeof(*key));
                    }
                }
            } else {
                ret = wc_SignatureVerify(
                          (enum wc_HashType)hash_type,
                          WC_SIGNATURE_TYPE_RSA_W_ENC,
                          msg_bytes, (word32)msg_len,
                          sig_bytes, (word32)sig_len,
                          key, sizeof(*key));
            }

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "RSA PKCS1 verify failed (%d)", ret); }
            } else {
                if (ret != 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "RSA PKCS1 accepted invalid"); }
            }
            free(msg_bytes); free(sig_bytes);
        }
        wc_FreeRsaKey(key);
        free(key);
    }
#else
    (void)root;
    (void)fname;
#endif
    return res;
}
