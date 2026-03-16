#include "runner.h"

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

test_result_t run_rsa_sig(const char *path)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_RSA
    cJSON *root, *groups, *group, *tests, *tc;
    const char *fname;

    root = load_json(path);
    if (!root) return res;

    fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;

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

        if (!key_ok) {
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
            uint8_t hash[WC_MAX_DIGEST_SIZE];
            uint8_t *dec_buf;
            int ret, dec_len, key_size;

            msg_bytes = get_hex(tc, "msg", &msg_len);
            sig_bytes = get_hex(tc, "sig", &sig_len);

            key_size = wc_RsaEncryptSize(key);
            dec_buf = (uint8_t *)malloc(key_size > 0 ? key_size : 1024);

            ret = wc_Hash((enum wc_HashType)hash_type,
                          msg_bytes, (word32)msg_len,
                          hash, (word32)hash_len);

            if (ret == 0 && dec_buf) {
                dec_len = wc_RsaSSL_Verify(sig_bytes, (word32)sig_len,
                                           dec_buf, key_size, key);
                if (dec_len < 0)
                    ret = dec_len;
                else if (dec_len != hash_len ||
                         memcmp(dec_buf, hash, hash_len) != 0)
                    ret = -1;
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
            free(msg_bytes); free(sig_bytes); free(dec_buf);
        }
        wc_FreeRsaKey(key);
        free(key);
    }
    cJSON_Delete(root);
#else
    (void)path;
#endif
    return res;
}
