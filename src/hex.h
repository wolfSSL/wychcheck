#ifndef WYCHCHECK_HEX_H
#define WYCHCHECK_HEX_H

#include <stddef.h>
#include <stdint.h>

/* Decode hex string into newly allocated buffer. Sets *out_len.
 * Returns NULL on invalid input or empty string (with *out_len = 0).
 * Caller must free() the result. */
uint8_t *hex_decode(const char *hex, size_t *out_len);

#endif
