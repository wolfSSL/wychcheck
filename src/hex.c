#include "hex.h"
#include <stdlib.h>
#include <string.h>

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

uint8_t *hex_decode(const char *hex, size_t *out_len)
{
    size_t len;
    uint8_t *buf;
    size_t i;

    *out_len = 0;
    if (!hex)
        return NULL;

    len = strlen(hex);
    if (len == 0) {
        buf = calloc(1, 1);
        return buf;
    }
    if (len % 2 != 0)
        return NULL;

    buf = malloc(len / 2);
    if (!buf)
        return NULL;

    for (i = 0; i < len; i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return NULL;
        }
        buf[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = len / 2;
    return buf;
}
