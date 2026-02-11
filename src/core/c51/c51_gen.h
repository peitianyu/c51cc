#ifndef C51_GEN_H
#define C51_GEN_H

#include "../obj.h"
#include "../ssa.h"

ObjFile *c51_gen(SSAUnit *unit);

int c51_write_asm(FILE *fp, const ObjFile *obj);
int c51_write_hex(FILE *fp, const ObjFile *obj);

#endif
