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

typedef test_result_t (*runner_fn)(const char *json_path);

typedef struct {
    const char *schema;
    runner_fn   run;
} runner_def_t;

/* Helper: load entire file into malloc'd string */
static inline char *load_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    long len;
    char *buf;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    if ((long)fread(buf, 1, len, f) != len) { free(buf); fclose(f); return NULL; }
    buf[len] = '\0';
    fclose(f);
    return buf;
}

/* Helper: load and parse JSON file */
static inline cJSON *load_json(const char *path)
{
    char *text = load_file(path);
    cJSON *root;
    if (!text) return NULL;
    root = cJSON_Parse(text);
    free(text);
    return root;
}

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
    return WC_MGF1NONE;
}

/* Helper: check result field */
static inline int is_valid(cJSON *tc)
{
    cJSON *r = cJSON_GetObjectItem(tc, "result");
    return r && cJSON_IsString(r) && strcmp(r->valuestring, "valid") == 0;
}

static inline int is_invalid(cJSON *tc)
{
    cJSON *r = cJSON_GetObjectItem(tc, "result");
    return r && cJSON_IsString(r) && strcmp(r->valuestring, "invalid") == 0;
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
test_result_t run_aead(const char *path);
test_result_t run_mac(const char *path);
test_result_t run_hkdf(const char *path);
test_result_t run_ind_cpa(const char *path);
test_result_t run_keywrap(const char *path);
test_result_t run_ecdh(const char *path);
test_result_t run_ecdsa(const char *path);
test_result_t run_ecdsa_p1363(const char *path);
test_result_t run_eddsa(const char *path);
test_result_t run_xdh(const char *path);
test_result_t run_rsa_sig(const char *path);
test_result_t run_rsa_oaep(const char *path);
test_result_t run_rsa_pss(const char *path);

#endif
