#include "runner.h"

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

test_result_t run_ecdsa_p1363(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *der_item = cJSON_GetObjectItem(group, "publicKeyDer");
        cJSON *sha_item = cJSON_GetObjectItem(group, "sha");
        uint8_t *pub_der;
        size_t pub_der_len;
        int hash_type;
        ecc_key key;
        int key_ok = 0;

        if (!der_item || !sha_item) continue;

        pub_der = hex_decode(der_item->valuestring, &pub_der_len);
        hash_type = wc_hash_type(sha_item->valuestring);

        if (hash_type == WC_HASH_TYPE_NONE || !pub_der) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            free(pub_der);
            continue;
        }

        wc_ecc_init(&key);
        {
            word32 idx = 0;
            if (wc_EccPublicKeyDecode(pub_der, &idx, &key,
                                      (word32)pub_der_len) == 0)
                key_ok = 1;
        }
        free(pub_der);

        if (!key_ok) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            wc_ecc_free(&key);
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *msg_bytes, *sig_bytes;
            size_t msg_len, sig_len;
            uint8_t hash[WC_MAX_DIGEST_SIZE];
            int hash_len;
            int stat = 0, ret;
            mp_int r_mp, s_mp;
            size_t half;

            msg_bytes = get_hex(tc, "msg", &msg_len);
            sig_bytes = get_hex(tc, "sig", &sig_len);

            hash_len = wc_HashGetDigestSize((enum wc_HashType)hash_type);
            ret = wc_Hash((enum wc_HashType)hash_type,
                          msg_bytes, (word32)msg_len,
                          hash, (word32)hash_len);

            /* P1363: sig = r || s, each half is exactly curve order size */
            half = (size_t)wc_ecc_size(&key);
            if (ret != 0 || sig_len != 2 * half) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ECDSA P1363 hash/sig len error");
                } else {
                    res.passed++;
                }
                free(msg_bytes); free(sig_bytes);
                continue;
            }
            mp_init(&r_mp);
            mp_init(&s_mp);
            mp_read_unsigned_bin(&r_mp, sig_bytes, (word32)half);
            mp_read_unsigned_bin(&s_mp, sig_bytes + half, (word32)half);

            ret = wc_ecc_verify_hash_ex(&r_mp, &s_mp,
                                        hash, (word32)hash_len,
                                        &stat, &key);

            mp_free(&r_mp);
            mp_free(&s_mp);

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0 && stat == 1) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "ECDSA P1363 verify failed (%d, stat=%d)", ret, stat); }
            } else {
                if (ret != 0 || stat == 0) res.passed++;
                else { res.failed++; FAIL_TC(fname, tc, "ECDSA P1363 accepted invalid"); }
            }

            free(msg_bytes); free(sig_bytes);
        }
        wc_ecc_free(&key);
    }
#else
    (void)root;
    (void)fname;
#endif
    return res;
}
