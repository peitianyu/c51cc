#ifndef C51CC_OBJ_H
#define C51CC_OBJ_H

#include "../obj.h"

/* asm interface */
ObjFile *c51_asm_from_text(const char *text, char **error, int *error_line);

/* output helpers (asm/hex) */
int c51_write_asm(FILE *fp, const ObjFile *obj);
int c51_write_hex(FILE *fp, const ObjFile *obj);

#endif /* C51CC_OBJ_H */
