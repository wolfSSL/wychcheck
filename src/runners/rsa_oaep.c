#include "runner.h"

#if !defined(NO_RSA) && defined(WC_RSA_OAEP)
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

test_result_t run_rsa_oaep(const char *path)
{
    test_result_t res = {0, 0, 0};
#if !defined(NO_RSA) && defined(WC_RSA_OAEP)
    cJSON *root, *groups, *group, *tests, *tc;
    const char *fname;
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0) return res;

    root = load_json(path);
    if (!root) { wc_FreeRng(&rng); return res; }

    fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *pkcs8_item = cJSON_GetObjectItem(group, "privateKeyPkcs8");
        cJSON *sha_item   = cJSON_GetObjectItem(group, "sha");
        cJSON *mgf_sha_item = cJSON_GetObjectItem(group, "mgfSha");
        uint8_t *pkcs8;
        size_t pkcs8_len;
        int hash_type, mgf;
        RsaKey *key;
        int key_ok = 0;

        if (!pkcs8_item || !sha_item) continue;

        pkcs8 = hex_decode(pkcs8_item->valuestring, &pkcs8_len);
        hash_type = wc_hash_type(sha_item->valuestring);
        mgf = wc_mgf_type(mgf_sha_item ? mgf_sha_item->valuestring : NULL);

        if (hash_type == WC_HASH_TYPE_NONE || !pkcs8) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            free(pkcs8);
            continue;
        }

        key = (RsaKey *)malloc(sizeof(RsaKey));
        if (!key) { free(pkcs8); continue; }

        wc_InitRsaKey(key, NULL);
        wc_RsaSetRNG(key, &rng);
        {
            word32 idx = 0;
            int trad_off = wc_GetPkcs8TraditionalOffset(pkcs8,
                               &idx, (word32)pkcs8_len);
            if (trad_off >= 0) {
                word32 rsa_idx = idx;
                if (wc_RsaPrivateKeyDecode(pkcs8, &rsa_idx, key,
                                           (word32)pkcs8_len) == 0)
                    key_ok = 1;
            }
        }
        free(pkcs8);

        if (!key_ok) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            wc_FreeRsaKey(key);
            free(key);
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *ct_bytes, *msg_exp, *label;
            size_t ct_len, msg_len, label_len;
            uint8_t *dec_buf;
            int ret, key_size;

            ct_bytes = get_hex(tc, "ct",    &ct_len);
            msg_exp  = get_hex(tc, "msg",   &msg_len);
            label    = get_hex(tc, "label", &label_len);

            key_size = wc_RsaEncryptSize(key);
            dec_buf = (uint8_t *)malloc(key_size > 0 ? key_size : 1024);

            if (dec_buf) {
                ret = wc_RsaPrivateDecrypt_ex(ct_bytes, (word32)ct_len,
                                              dec_buf, key_size,
                                              key,
                                              WC_RSA_OAEP_PAD,
                                              (enum wc_HashType)hash_type,
                                              mgf,
                                              label_len > 0 ? label : NULL,
                                              (word32)label_len);
            } else {
                ret = -1;
            }

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret >= 0 && (size_t)ret == msg_len &&
                    memcmp(dec_buf, msg_exp, msg_len) == 0)
                    res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "RSA OAEP decrypt failed (%d)", ret); }
            } else {
                if (ret < 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "RSA OAEP accepted invalid"); }
            }

            free(ct_bytes); free(msg_exp); free(label); free(dec_buf);
        }
        wc_FreeRsaKey(key);
        free(key);
    }

    cJSON_Delete(root);
    wc_FreeRng(&rng);
#else
    (void)path;
#endif
    return res;
}
