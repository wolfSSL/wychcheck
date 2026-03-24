#include "runner.h"

#ifdef HAVE_CURVE25519
#include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_CURVE448
#include <wolfssl/wolfcrypt/curve448.h>
#endif

test_result_t run_xdh(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
    cJSON *groups, *group, *tests, *tc;

    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups) {
        cJSON *curve_item = cJSON_GetObjectItem(group, "curve");
        const char *curve = curve_item ? curve_item->valuestring : "";
        int is_x25519 = (strcmp(curve, "curve25519") == 0);
        int is_x448   = (strcmp(curve, "curve448") == 0);

        if (!is_x25519 && !is_x448) {
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *pub, *priv, *shared_exp;
            size_t pub_len, priv_len, shared_len;

            pub        = get_hex(tc, "public",  &pub_len);
            priv       = get_hex(tc, "private", &priv_len);
            shared_exp = get_hex(tc, "shared",  &shared_len);

#ifdef HAVE_CURVE25519
            if (is_x25519) {
                curve25519_key pub_key, priv_key;
                uint8_t shared_out[CURVE25519_KEYSIZE];
                word32 shared_out_len = sizeof(shared_out);
                int ret;

                wc_curve25519_init(&pub_key);
                wc_curve25519_init(&priv_key);

                ret = wc_curve25519_import_public_ex(pub, (word32)pub_len,
                                                     &pub_key,
                                                     EC25519_LITTLE_ENDIAN);
                if (ret == 0)
                    ret = wc_curve25519_import_private_ex(priv, (word32)priv_len,
                                                         &priv_key,
                                                         EC25519_LITTLE_ENDIAN);
                if (ret == 0)
                    ret = wc_curve25519_shared_secret_ex(&priv_key, &pub_key,
                                                        shared_out,
                                                        &shared_out_len,
                                                        EC25519_LITTLE_ENDIAN);

                if (is_acceptable(tc)) {
                    res.passed++;
                } else if (is_valid(tc)) {
                    if (ret == 0 && shared_out_len == (word32)shared_len &&
                        memcmp(shared_out, shared_exp, shared_len) == 0)
                        res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "X25519 failed (%d)", ret); }
                } else {
                    if (ret != 0) res.passed++;
                    else if (shared_out_len != (word32)shared_len ||
                             memcmp(shared_out, shared_exp, shared_len) != 0)
                        res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "X25519 accepted invalid"); }
                }

                wc_curve25519_free(&pub_key);
                wc_curve25519_free(&priv_key);
            }
#else
            if (is_x25519) { res.skipped++; }
#endif

#ifdef HAVE_CURVE448
            if (is_x448) {
                curve448_key pub_key, priv_key;
                uint8_t shared_out[CURVE448_KEY_SIZE];
                word32 shared_out_len = sizeof(shared_out);
                int ret;

                wc_curve448_init(&pub_key);
                wc_curve448_init(&priv_key);

                ret = wc_curve448_import_public_ex(pub, (word32)pub_len,
                                                   &pub_key,
                                                   EC448_LITTLE_ENDIAN);
                if (ret == 0)
                    ret = wc_curve448_import_private_ex(priv, (word32)priv_len,
                                                       &priv_key,
                                                       EC448_LITTLE_ENDIAN);
                if (ret == 0)
                    ret = wc_curve448_shared_secret_ex(&priv_key, &pub_key,
                                                      shared_out,
                                                      &shared_out_len,
                                                      EC448_LITTLE_ENDIAN);

                if (is_acceptable(tc)) {
                    res.passed++;
                } else if (is_valid(tc)) {
                    if (ret == 0 && shared_out_len == (word32)shared_len &&
                        memcmp(shared_out, shared_exp, shared_len) == 0)
                        res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "X448 failed (%d)", ret); }
                } else {
                    if (ret != 0) res.passed++;
                    else if (shared_out_len != (word32)shared_len ||
                             memcmp(shared_out, shared_exp, shared_len) != 0)
                        res.passed++;
                    else { res.failed++; FAIL_TC(fname, tc, "X448 accepted invalid"); }
                }

                wc_curve448_free(&pub_key);
                wc_curve448_free(&priv_key);
            }
#else
            if (is_x448) { res.skipped++; }
#endif
            free(pub); free(priv); free(shared_exp);
        }
    }
#else
    (void)root;
    (void)fname;
#endif
    return res;
}
