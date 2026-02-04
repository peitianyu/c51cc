#include "c51_obj.h"
#include <stdio.h>

static void hex_record(FILE *fp, unsigned char type, unsigned short addr, const unsigned char *data, int len)
{
    unsigned char sum = (unsigned char)(len + (addr >> 8) + (addr & 0xFF) + type);
    fprintf(fp, ":%02X%04X%02X", len, addr, type);
    for (int i = 0; i < len; ++i) {
        sum += data[i];
        fprintf(fp, "%02X", data[i]);
    }
    sum = (unsigned char)(~sum + 1);
    fprintf(fp, "%02X\n", sum);
}

int c51_write_hex(FILE *fp, const ObjFile *obj)
{
    if (!fp || !obj) return -1;
    Section *code = NULL;
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) { code = sec; break; }
    }
    if (!code || !code->bytes || code->bytes_len == 0) {
        hex_record(fp, 0x01, 0, NULL, 0);
        return 0;
    }

    unsigned short addr = 0;
    int i = 0;
    while (i < code->bytes_len) {
        int chunk = code->bytes_len - i;
        if (chunk > 16) chunk = 16;
        hex_record(fp, 0x00, addr, code->bytes + i, chunk);
        addr += (unsigned short)chunk;
        i += chunk;
    }
    hex_record(fp, 0x01, 0, NULL, 0);
    return 0;
}
