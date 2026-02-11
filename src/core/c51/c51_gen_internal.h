#ifndef __C51_INTERNAL_H
#define __C51_INTERNAL_H

#include "c51_gen.h"

typedef struct C51GenContext {
    ObjFile* obj;
    Func* current_func;
    Block* current_block;

    Dict* value_to_reg;
    Dict* value_to_addr;
    Dict* value_type;

    Dict* v16_regs;
    int next_v16_offset;

    Dict* mmio_map;
    int label_counter;

    List* temp_values;
} C51GenContext;

C51GenContext* c51_ctx_new(void);
void c51_ctx_free(C51GenContext* ctx);

void c51_instr(C51GenContext* ctx, Section* sec, Instr* ins);
void c51_regalloc(C51GenContext* ctx, Section* sec);
void c51_optimize(C51GenContext* ctx, Section* sec);
void c51_encode(C51GenContext* ctx, Section* sec);

#endif