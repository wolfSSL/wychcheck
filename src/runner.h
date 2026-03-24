#ifndef WYCHCHECK_RUNNER_H
#define WYCHCHECK_RUNNER_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "cjson/cJSON.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int passed;
    int failed;
    int skipped;
} test_result_t;

typedef test_result_t (*runner_fn)(cJSON *root, const char *fname);

typedef struct {
    const char *schema;
    runner_fn   run;
} runner_def_t;

/* Helper: get hex-decoded field from cJSON object.
 * Returns malloc'd buffer, sets *len. Returns NULL if field missing/empty. */
static inline uint8_t *get_hex(cJSON *obj, const char *field, size_t *len)
{
    cJSON *item = cJSON_GetObjectItem(obj, field);
    *len = 0;
    if (!item || !cJSON_IsString(item))
        return NULL;
    return hex_decode(item->valuestring, len);
}

/* Helper: map Wycheproof hash name to wolfcrypt hash type */
static inline int wc_hash_type(const char *name)
{
    if (!name) return WC_HASH_TYPE_NONE;
    if (strcmp(name, "SHA-1") == 0)   return WC_HASH_TYPE_SHA;
    if (strcmp(name, "SHA-224") == 0) return WC_HASH_TYPE_SHA224;
    if (strcmp(name, "SHA-256") == 0) return WC_HASH_TYPE_SHA256;
    if (strcmp(name, "SHA-384") == 0) return WC_HASH_TYPE_SHA384;
    if (strcmp(name, "SHA-512") == 0) return WC_HASH_TYPE_SHA512;
#ifdef WOLFSSL_SHA512
    if (strcmp(name, "SHA-512/224") == 0) return WC_HASH_TYPE_SHA512_224;
    if (strcmp(name, "SHA-512/256") == 0) return WC_HASH_TYPE_SHA512_256;
#endif
#ifdef WOLFSSL_SHA3
    if (strcmp(name, "SHA3-224") == 0) return WC_HASH_TYPE_SHA3_224;
    if (strcmp(name, "SHA3-256") == 0) return WC_HASH_TYPE_SHA3_256;
    if (strcmp(name, "SHA3-384") == 0) return WC_HASH_TYPE_SHA3_384;
    if (strcmp(name, "SHA3-512") == 0) return WC_HASH_TYPE_SHA3_512;
#endif
    return WC_HASH_TYPE_NONE;
}

/* Helper: map Wycheproof MGF name to wolfcrypt MGF id */
static inline int wc_mgf_type(const char *mgfSha)
{
    if (!mgfSha) return WC_MGF1NONE;
    if (strcmp(mgfSha, "SHA-1") == 0)   return WC_MGF1SHA1;
    if (strcmp(mgfSha, "SHA-224") == 0) return WC_MGF1SHA224;
    if (strcmp(mgfSha, "SHA-256") == 0) return WC_MGF1SHA256;
    if (strcmp(mgfSha, "SHA-384") == 0) return WC_MGF1SHA384;
    if (strcmp(mgfSha, "SHA-512") == 0) return WC_MGF1SHA512;
#ifdef WOLFSSL_SHA512
    if (strcmp(mgfSha, "SHA-512/224") == 0) return WC_MGF1SHA512_224;
    if (strcmp(mgfSha, "SHA-512/256") == 0) return WC_MGF1SHA512_256;
#endif
    return WC_MGF1NONE;
}

/* Helper: check Wycheproof result field.
 * "valid" = must succeed, "invalid" = must fail,
 * "acceptable" = implementation-defined, counted as pass either way. */
static inline int is_valid(cJSON *tc)
{
    cJSON *r = cJSON_GetObjectItem(tc, "result");
    return r && cJSON_IsString(r) && strcmp(r->valuestring, "valid") == 0;
}

static inline int is_acceptable(cJSON *tc)
{
    cJSON *r = cJSON_GetObjectItem(tc, "result");
    return r && cJSON_IsString(r) && strcmp(r->valuestring, "acceptable") == 0;
}

static inline int get_tcid(cJSON *tc)
{
    cJSON *id = cJSON_GetObjectItem(tc, "tcId");
    return id ? id->valueint : -1;
}

#define FAIL_TC(file, tc, fmt, ...) \
    fprintf(stderr, "  FAIL %s tcId=%d: " fmt "\n", file, get_tcid(tc), ##__VA_ARGS__)

/* Runner declarations */
test_result_t run_aead(cJSON *root, const char *fname);
test_result_t run_mac(cJSON *root, const char *fname);
test_result_t run_hkdf(cJSON *root, const char *fname);
test_result_t run_ind_cpa(cJSON *root, const char *fname);
test_result_t run_keywrap(cJSON *root, const char *fname);
test_result_t run_ecdh(cJSON *root, const char *fname);
test_result_t run_ecdsa(cJSON *root, const char *fname);
test_result_t run_ecdsa_p1363(cJSON *root, const char *fname);
test_result_t run_eddsa(cJSON *root, const char *fname);
test_result_t run_xdh(cJSON *root, const char *fname);
test_result_t run_rsa_sig(cJSON *root, const char *fname);
test_result_t run_rsa_oaep(cJSON *root, const char *fname);
test_result_t run_rsa_pss(cJSON *root, const char *fname);

#endif
