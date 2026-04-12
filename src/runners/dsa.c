#include "runner.h"

/*
 * Runners for Wycheproof DSA test vectors.
 *
 * Two schemas are covered by two runner functions in this file:
 *
 *   dsa_verify_schema_v1.json      — DER-encoded signatures
 *                                    (ASN.1 SEQUENCE { r INTEGER, s INTEGER })
 *   dsa_p1363_verify_schema_v1.json — P1363 / IEEE 1363 signatures
 *                                    (raw r || s, fixed length)
 *
 * wolfSSL's wc_DsaVerify_ex() always takes raw r||s, so DER signatures are
 * decoded to raw form before calling it.  The public key is imported from the
 * DER-encoded SubjectPublicKeyInfo in the "publicKeyDer" group field.
 *
 * Feature guard: NO_DSA (DSA is compiled in by default; define NO_DSA to
 * disable).  wolfSSL must be built without NO_DSA.
 */

#ifndef NO_DSA
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/* Maximum size of raw r or s for any supported DSA key size.
 * DSA_MAX_HALF_SIZE is defined in wolfssl/wolfcrypt/dsa.h (= 32 bytes
 * for a 256-bit q).  We double it to get the raw sig buffer size. */
#define DSA_RAW_SIG_MAX (DSA_MAX_HALF_SIZE * 2)

/*
 * Decode a DER-encoded DSA signature:
 *   SEQUENCE { r INTEGER, s INTEGER }
 * into a raw r||s buffer, each component zero-padded to qSz bytes
 * (big-endian).  Returns 0 on success, -1 on any parse error.
 */
static int dsa_decode_der_sig(const uint8_t *sig, size_t sig_len,
                               uint8_t *out, int qSz)
{
    size_t idx = 0;
    int i;

    /* SEQUENCE tag */
    if (idx >= sig_len || sig[idx++] != 0x30)
        return -1;

    /* SEQUENCE length — single-byte or multi-byte.  We trust sig_len
     * for the outer bound, so we just skip the encoded length. */
    if (idx >= sig_len)
        return -1;
    if (sig[idx] & 0x80) {
        int lbytes = sig[idx++] & 0x7f;
        if ((int)(sig_len - idx) < lbytes)
            return -1;
        idx += (size_t)lbytes;
    } else {
        idx++;
    }

    /* Parse r and then s */
    for (i = 0; i < 2; i++) {
        int ilen;
        uint8_t *dest = out + i * qSz;

        /* INTEGER tag */
        if (idx >= sig_len || sig[idx++] != 0x02)
            return -1;
        if (idx >= sig_len)
            return -1;

        /* INTEGER length — DER requires the shortest encoding.  For DSA
         * parameters r and s, the maximum value is qSz bytes (≤ 32) plus
         * at most one leading 0x00 sign byte, so the length always fits in
         * a single byte (< 128).  Reject long-form (BER) integer lengths:
         * they are never valid DER, and a negative ilen from multi-byte
         * overflow would bypass the bounds check and crash via memcpy. */
        if (sig[idx] & 0x80)
            return -1;
        ilen = sig[idx++];
        if ((int)(sig_len - idx) < ilen)
            return -1;

        /* DER encodes positive integers with a leading 0x00 when the
         * high bit of the first value byte would otherwise be set.
         * Strip that padding byte before copying into the raw buffer. */
        if (ilen > 0 && sig[idx] == 0x00) {
            ilen--;
            idx++;
        }

        /* After stripping the sign byte, r or s must fit in qSz bytes. */
        if (ilen > qSz)
            return -1;

        /* Zero-pad on the left, copy value right-aligned (big-endian). */
        memset(dest, 0, (size_t)qSz);
        memcpy(dest + (qSz - ilen), sig + idx, (size_t)ilen);
        idx += (size_t)ilen;
    }

    return 0;
}

/* Core per-group verification loop.  p1363=1 means the sig field is raw
 * r||s (IEEE 1363); p1363=0 means DER SEQUENCE{r,s} that must be decoded. */
static void dsa_run_group(cJSON *group, const char *fname, int p1363,
                           test_result_t *res)
{
    cJSON *der_item = cJSON_GetObjectItem(group, "publicKeyDer");
    cJSON *sha_item = cJSON_GetObjectItem(group, "sha");
    cJSON *tests, *tc;
    uint8_t *pub_der = NULL;
    size_t   pub_der_len = 0;
    int hash_type;
    DsaKey key;
    int key_inited = 0;
    int qSz;

    if (!der_item || !sha_item)
        goto skip_group;

    hash_type = wc_hash_type(sha_item->valuestring);
    if (hash_type == WC_HASH_TYPE_NONE)
        goto skip_group;

    pub_der = hex_decode(der_item->valuestring, &pub_der_len);
    if (!pub_der)
        goto skip_group;

    if (wc_InitDsaKey(&key) != 0)
        goto skip_group;
    key_inited = 1;

    {
        word32 idx = 0;
        if (wc_DsaPublicKeyDecode(pub_der, &idx, &key,
                                  (word32)pub_der_len) != 0)
            goto skip_group;
    }

    /* qSz: number of bytes in q, used to size the raw signature buffer. */
    qSz = mp_unsigned_bin_size(&key.q);
    if (qSz <= 0 || qSz > DSA_MAX_HALF_SIZE)
        goto skip_group;

    free(pub_der);
    pub_der = NULL;

    tests = cJSON_GetObjectItem(group, "tests");
    cJSON_ArrayForEach(tc, tests) {
        uint8_t *msg_bytes = NULL, *sig_bytes = NULL;
        size_t   msg_len = 0, sig_len = 0;
        uint8_t  hash[WC_MAX_DIGEST_SIZE];
        uint8_t  raw_sig[DSA_RAW_SIG_MAX];
        int      hash_len, ret, answer = 0;

        msg_bytes = get_hex(tc, "msg", &msg_len);
        sig_bytes = get_hex(tc, "sig", &sig_len);

        if (!msg_bytes || !sig_bytes) {
            res->skipped++;
            goto tc_next;
        }

        hash_len = wc_HashGetDigestSize((enum wc_HashType)hash_type);
        if (hash_len <= 0) {
            res->skipped++;
            goto tc_next;
        }

        ret = wc_Hash((enum wc_HashType)hash_type,
                      msg_bytes, (word32)msg_len,
                      hash, (word32)hash_len);
        if (ret != 0) {
            res->skipped++;
            goto tc_next;
        }

        /* FIPS 186-4 §4.6: use the leftmost min(hash_len, qSz) bytes of
         * the digest.  wc_DsaVerify_ex reads exactly digestSz bytes from
         * the front of the hash buffer, so passing the truncated length
         * implements the standard bit-truncation correctly. */
        int vhlen = (hash_len < qSz) ? hash_len : qSz;

        if (p1363) {
            /* P1363: sig_bytes is already raw r||s.
             * Validate exact length; a wrong-length sig cannot be valid. */
            if ((int)sig_len != 2 * qSz) {
                answer = 0;  /* treat as verify failure */
                ret = 0;
                /* fall through to result check */
            } else {
                ret = wc_DsaVerify_ex(hash, (word32)vhlen,
                                      sig_bytes, &key, &answer);
            }
        } else {
            /* DER: decode SEQUENCE{r,s} → raw r||s */
            if (dsa_decode_der_sig(sig_bytes, sig_len, raw_sig, qSz) != 0) {
                answer = 0;
                ret = 0;
            } else {
                ret = wc_DsaVerify_ex(hash, (word32)vhlen,
                                      raw_sig, &key, &answer);
            }
        }

        if (is_acceptable(tc)) {
            res->passed++;
        } else if (is_valid(tc)) {
            if (ret == 0 && answer == 1)
                res->passed++;
            else {
                res->failed++;
                FAIL_TC(fname, tc, "DSA verify failed (ret=%d, answer=%d)",
                        ret, answer);
            }
        } else {
            /* invalid: expect rejection */
            if (ret != 0 || answer == 0)
                res->passed++;
            else {
                res->failed++;
                FAIL_TC(fname, tc, "DSA accepted invalid sig");
            }
        }

    tc_next:
        free(msg_bytes);
        free(sig_bytes);
    }

    wc_FreeDsaKey(&key);
    return;

skip_group:
    free(pub_der);
    if (key_inited)
        wc_FreeDsaKey(&key);
    tests = cJSON_GetObjectItem(group, "tests");
    cJSON_ArrayForEach(tc, tests) { res->skipped++; }
}

#endif /* !NO_DSA */


/* ------------------------------------------------------------------ */

test_result_t run_dsa(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_DSA
    cJSON *groups, *group;
    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups)
        dsa_run_group(group, fname, /*p1363=*/0, &res);
#else
    (void)root; (void)fname;
#endif
    return res;
}


test_result_t run_dsa_p1363(cJSON *root, const char *fname)
{
    test_result_t res = {0, 0, 0};
#ifndef NO_DSA
    cJSON *groups, *group;
    groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON_ArrayForEach(group, groups)
        dsa_run_group(group, fname, /*p1363=*/1, &res);
#else
    (void)root; (void)fname;
#endif
    return res;
}
