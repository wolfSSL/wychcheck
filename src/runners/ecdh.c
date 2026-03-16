#include "runner.h"

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

static int curve_id_from_name(const char *name)
{
    if (strcmp(name, "secp256r1") == 0) return ECC_SECP256R1;
    if (strcmp(name, "secp384r1") == 0) return ECC_SECP384R1;
    if (strcmp(name, "secp521r1") == 0) return ECC_SECP521R1;
#ifdef HAVE_ECC_SECPR2
    if (strcmp(name, "secp224r1") == 0) return ECC_SECP224R1;
#endif
#ifdef HAVE_ECC_KOBLITZ
    if (strcmp(name, "secp256k1") == 0) return ECC_SECP256K1;
#endif
#ifdef HAVE_ECC_BRAINPOOL
    if (strcmp(name, "brainpoolP256r1") == 0) return ECC_BRAINPOOLP256R1;
    if (strcmp(name, "brainpoolP384r1") == 0) return ECC_BRAINPOOLP384R1;
    if (strcmp(name, "brainpoolP512r1") == 0) return ECC_BRAINPOOLP512R1;
#endif
    return -1;
}
#endif /* HAVE_ECC */

test_result_t run_ecdh(const char *path)
{
    test_result_t res = {0, 0, 0};
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
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
        cJSON *curve_item = cJSON_GetObjectItem(group, "curve");
        cJSON *enc_item = cJSON_GetObjectItem(group, "encoding");
        const char *curve_name = curve_item ? curve_item->valuestring : "";
        const char *encoding = enc_item ? enc_item->valuestring : "asn";
        int curve_id = curve_id_from_name(curve_name);

        if (curve_id < 0) {
            /* unsupported curve, skip all tests in group */
            tests = cJSON_GetObjectItem(group, "tests");
            cJSON_ArrayForEach(tc, tests) { res.skipped++; }
            continue;
        }

        tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(tc, tests) {
            uint8_t *pub_bytes, *priv_bytes, *shared_exp;
            size_t pub_len, priv_len, shared_len;
            ecc_key pub_key, priv_key;
            uint8_t shared_out[256];
            word32 shared_out_len = sizeof(shared_out);
            int ret;

            pub_bytes   = get_hex(tc, "public",  &pub_len);
            priv_bytes  = get_hex(tc, "private", &priv_len);
            shared_exp  = get_hex(tc, "shared",  &shared_len);

            wc_ecc_init(&pub_key);
            wc_ecc_init(&priv_key);
            wc_ecc_set_rng(&priv_key, &rng);

            /* import public key */
            if (strcmp(encoding, "asn") == 0) {
                word32 idx = 0;
                ret = wc_EccPublicKeyDecode(pub_bytes, &idx,
                                            &pub_key, (word32)pub_len);
            } else {
                /* ecpoint: raw uncompressed point */
                ret = wc_ecc_import_x963_ex(pub_bytes, (word32)pub_len,
                                            &pub_key, curve_id);
            }

            if (ret != 0) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ECDH pub import failed (%d)", ret);
                } else {
                    res.passed++;
                }
                goto ecdh_next;
            }

            /* import private key: raw scalar + curve */
            ret = wc_ecc_import_private_key_ex(priv_bytes, (word32)priv_len,
                                               NULL, 0, &priv_key, curve_id);
            if (ret != 0) {
                if (is_valid(tc)) {
                    res.failed++;
                    FAIL_TC(fname, tc, "ECDH priv import failed (%d)", ret);
                } else {
                    res.passed++;
                }
                goto ecdh_next;
            }

            ret = wc_ecc_shared_secret(&priv_key, &pub_key,
                                       shared_out, &shared_out_len);

            if (is_acceptable(tc)) {
                res.passed++;
            } else if (is_valid(tc)) {
                if (ret == 0 && shared_out_len == (word32)shared_len &&
                    memcmp(shared_out, shared_exp, shared_len) == 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "ECDH shared secret mismatch (%d)", ret);
                }
            } else {
                /* invalid: either import should have failed or shared secret
                 * should differ */
                if (ret != 0) res.passed++;
                else if (shared_out_len != (word32)shared_len ||
                         memcmp(shared_out, shared_exp, shared_len) != 0)
                    res.passed++;
                else {
                    res.failed++;
                    FAIL_TC(fname, tc, "ECDH accepted invalid");
                }
            }

        ecdh_next:
            wc_ecc_free(&pub_key);
            wc_ecc_free(&priv_key);
            free(pub_bytes); free(priv_bytes); free(shared_exp);
        }
    }

    cJSON_Delete(root);
    wc_FreeRng(&rng);
#else
    (void)path;
#endif
    return res;
}
