#ifndef WOLFCRYPT_CHECK_HEX_H
#define WOLFCRYPT_CHECK_HEX_H

#include <stddef.h>
#include <stdint.h>

/* Decode hex string into newly allocated buffer. Sets *out_len.
 * Returns NULL on NULL or invalid input (odd length, bad hex chars).
 * For an empty string, returns a zero-length allocated buffer (*out_len = 0);
 * caller must still free() the result. */
uint8_t *hex_decode(const char *hex, size_t *out_len);

#endif
