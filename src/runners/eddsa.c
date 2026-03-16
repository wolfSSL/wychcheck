#include "runner.h"

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif

test_result_t run_eddsa(const char *path)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    cJSON *root, *groups, *group, *tests, *tc;
    const char *fname;

    root = load_json(path);
    if (!root) return res;

    fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *pk_obj = cJSON_GetObjectItem(group, "publicKey");
        cJSON *pk_hex_item = pk_obj ? cJSON_GetObjectItem(pk_obj, "pk") : NULL;
        cJSON *curve_item = pk_obj ? cJSON_GetObjectItem(pk_obj, "curve") : NULL;
        const char *curve;
        uint8_t *pk_bytes;
        size_t pk_len;
        int is_ed25519 = 0, is_ed448 = 0;

        if (!pk_hex_item || !curve_item) continue;
        curve = curve_item->valuestring;

        if (strcmp(curve, "edwards25519") == 0) is_ed25519 = 1;
        else if (strcmp(curve, "edwards448") == 0) is_ed448 = 1;
        else {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        pk_bytes = hex_decode(pk_hex_item->valuestring, &pk_len);

#ifdef HAVE_ED25519
        if (is_ed25519) {
            ed25519_key key;
            wc_ed25519_init(&key);
            if (wc_ed25519_import_public(pk_bytes, (word32)pk_len, &key) != 0) {
                tests = cJSON_GetObjectItem(group, "tests");
                cJSON_ArrayForEach(tc, tests) { res.skipped++; }
                wc_ed25519_free(&key);
                free(pk_bytes);
                continue;
            }

            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) {
                uint8_t *msg, *sig;
                size_t msg_len, sig_len;
                int stat = 0, ret;

                msg = get_hex(tc, "msg", &msg_len);
                sig = get_hex(tc, "sig", &sig_len);

                ret = wc_ed25519_verify_msg(sig, (word32)sig_len,
                                            msg, (word32)msg_len,
                                            &stat, &key);

                if (is_acceptable(tc)) {
                    res.passed++;
                } else if (is_valid(tc)) {
                    if (ret == 0 && stat == 1) res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "Ed25519 verify failed (%d, stat=%d)", ret, stat); }
                } else {
                    if (ret != 0 || stat == 0) res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "Ed25519 accepted invalid"); }
                }
                free(msg); free(sig);
            }
            wc_ed25519_free(&key);
        }
#else
        if (is_ed25519) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
        }
#endif

#ifdef HAVE_ED448
        if (is_ed448) {
            ed448_key key;
            wc_ed448_init(&key);
            if (wc_ed448_import_public(pk_bytes, (word32)pk_len, &key) != 0) {
                tests = cJSON_GetObjectItem(group, "tests");
                cJSON_ArrayForEach(tc, tests) { res.skipped++; }
                wc_ed448_free(&key);
                free(pk_bytes);
                continue;
            }

            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) {
                uint8_t *msg, *sig;
                size_t msg_len, sig_len;
                int stat = 0, ret;

                msg = get_hex(tc, "msg", &msg_len);
                sig = get_hex(tc, "sig", &sig_len);

                ret = wc_ed448_verify_msg(sig, (word32)sig_len,
                                          msg, (word32)msg_len,
                                          &stat, &key,
                                          NULL, 0); /* no context */

                if (is_acceptable(tc)) {
                    res.passed++;
                } else if (is_valid(tc)) {
                    if (ret == 0 && stat == 1) res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "Ed448 verify failed (%d, stat=%d)", ret, stat); }
                } else {
                    if (ret != 0 || stat == 0) res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "Ed448 accepted invalid"); }
                }
                free(msg); free(sig);
            }
            wc_ed448_free(&key);
        }
#else
        if (is_ed448) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
        }
#endif
        free(pk_bytes);
    }
    cJSON_Delete(root);
#else
    (void)path;
#endif
    return res;
}
