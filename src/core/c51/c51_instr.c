#include "c51_gen_internal.h"
#include <stdio.h>
#include <stdlib.h>

static char* instr_to_ssa_str(Instr *ins)
{
    if (!ins) return strdup("");

    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return strdup("");
    ssa_print_instr(f, ins, NULL);
    fclose(f);
    if (!buf) return strdup("");
    char *p = buf;
    while (*p == ' ' || *p == '\t') p++;
    size_t blen = strlen(p);
    while (blen > 0 && (p[blen-1] == '\n' || p[blen-1] == '\r')) p[--blen] = '\0';
    char *out = malloc(blen + 3);
    if (out) sprintf(out, "; %s", p);
    free(buf);
    return out ? out : strdup("");

}

static void emit_mov(C51GenContext* ctx, Section* sec, const char* dst, const char* src, Instr* ins)
{
    (void)ctx;
    char *ssa = instr_to_ssa_str(ins);
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "MOV %s, %s", dst, src);
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("MOV");
    ai->args = make_list();
    list_push(ai->args, strdup(dst));
    list_push(ai->args, strdup(src));
    ai->ssa = ssa;
    list_push(sec->asminstrs, ai);
}

static void emit_unary(C51GenContext* ctx, Section* sec, const char* op, const char* operand, Instr* ins)
{
    (void)ctx;
    char *ssa = instr_to_ssa_str(ins);
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup(op);
    ai->args = make_list();
    list_push(ai->args, strdup(operand));
    ai->ssa = ssa;
    list_push(sec->asminstrs, ai);
}

static char* int_to_key(int n)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", n);
    return strdup(buf);
}

static void emit_const(C51GenContext* ctx, Section* sec, Instr* ins)
{
    int size = ins->type ? ins->type->size : 1;
    
    if (size == 1) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(ins->imm.ival & 0xFF));
        emit_mov(ctx, sec, "R7", imm_str, ins);
        
        int* reg_num = malloc(sizeof(int));
        *reg_num = 7;
        dict_put(ctx->value_to_reg, int_to_key(ins->dest), reg_num);
    } else if (size == 2) {
        char imm_high[16], imm_low[16];
        int val = (int)(ins->imm.ival & 0xFFFF);
        snprintf(imm_high, sizeof(imm_high), "#%d", (val >> 8) & 0xFF);
        snprintf(imm_low, sizeof(imm_low), "#%d", val & 0xFF);
        
        emit_mov(ctx, sec, "R6", imm_high, ins);
        emit_mov(ctx, sec, "R7", imm_low, ins);
        
        int* reg_num = malloc(sizeof(int));
        *reg_num = 6;
        dict_put(ctx->value_to_reg, int_to_key(ins->dest), reg_num);
    }
}

static void emit_arith(C51GenContext* ctx, Section* sec, Instr* ins, const char* op)
{
    (void)ctx;
    ValueName lhs = 0, rhs = 0;
    if (ins->args && ins->args->len >= 2) {
        lhs = *(ValueName*)list_get(ins->args, 0);
        rhs = *(ValueName*)list_get(ins->args, 1);
    }
    (void)lhs;
    (void)rhs;
    
    char *ssa = instr_to_ssa_str(ins);
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup(op);
    ai->args = make_list();
    list_push(ai->args, strdup("A"));
    list_push(ai->args, strdup("R5"));
    ai->ssa = ssa;
    list_push(sec->asminstrs, ai);
    
    int* reg_num = malloc(sizeof(int));
    *reg_num = 6;
    dict_put(ctx->value_to_reg, int_to_key(ins->dest), reg_num);
}

static void emit_add(C51GenContext* ctx, Section* sec, Instr* ins)
{
    emit_mov(ctx, sec, "A", "R7", ins);
    
    char *ssa = instr_to_ssa_str(ins);
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("ADD");
    ai->args = make_list();
    list_push(ai->args, strdup("A"));
    list_push(ai->args, strdup("R5"));
    ai->ssa = ssa;
    list_push(sec->asminstrs, ai);
    
    emit_mov(ctx, sec, "R7", "A", ins);
    
    emit_mov(ctx, sec, "A", "R6", ins);
    
    char *ssa2 = instr_to_ssa_str(ins);
    ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("ADDC");
    ai->args = make_list();
    list_push(ai->args, strdup("A"));
    list_push(ai->args, strdup("R4"));
    ai->ssa = ssa2;
    list_push(sec->asminstrs, ai);
    
    emit_mov(ctx, sec, "R6", "A", ins);
    
    int* reg_num = malloc(sizeof(int));
    *reg_num = 6;
    dict_put(ctx->value_to_reg, int_to_key(ins->dest), reg_num);
}

static void emit_sub(C51GenContext* ctx, Section* sec, Instr* ins)
{
    emit_unary(ctx, sec, "CLR", "C", ins);
    
    emit_mov(ctx, sec, "A", "R7", ins);
    
    char *ssa = instr_to_ssa_str(ins);
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("SUBB");
    ai->args = make_list();
    list_push(ai->args, strdup("A"));
    list_push(ai->args, strdup("R5"));
    ai->ssa = ssa;
    list_push(sec->asminstrs, ai);
    
    emit_mov(ctx, sec, "R7", "A", ins);
    
    emit_mov(ctx, sec, "A", "R6", ins);
    
    char *ssa2 = instr_to_ssa_str(ins);
    ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("SUBB");
    ai->args = make_list();
    list_push(ai->args, strdup("A"));
    list_push(ai->args, strdup("R4"));
    ai->ssa = ssa2;
    list_push(sec->asminstrs, ai);
    
    emit_mov(ctx, sec, "R6", "A", ins);

    int* reg_num = malloc(sizeof(int));
    *reg_num = 6;
    dict_put(ctx->value_to_reg, int_to_key(ins->dest), reg_num);
}

static void emit_ret(C51GenContext* ctx, Section* sec, Instr* ins)
{
    (void)ctx;
    
    char *ssa = instr_to_ssa_str(ins);
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("RET");
    ai->args = make_list();
    ai->ssa = ssa;
    list_push(sec->asminstrs, ai);
}

static void emit_inline_asm(C51GenContext* ctx, Section* sec, const char* asm_text, Instr* ins)
{
    (void)ctx;
    (void)ins;
    AsmInstr* ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup("; ASM");
    ai->args = make_list();
    ai->ssa = strdup(asm_text);
    list_push(sec->asminstrs, ai);
}

void c51_instr(C51GenContext* ctx, Section* sec, Instr* ins)
{
    if (!ctx || !sec || !ins) return;
    
    switch (ins->op) {
        case IROP_NOP:
            break;
            
        case IROP_CONST:
            emit_const(ctx, sec, ins);
            break;
            
        case IROP_PARAM:
            break;
            
        case IROP_ADD:
            emit_add(ctx, sec, ins);
            break;
            
        case IROP_SUB:
            emit_sub(ctx, sec, ins);
            break;
            
        case IROP_RET:
            emit_ret(ctx, sec, ins);
            break;
            
        case IROP_ASM:
            if (ins->labels && ins->labels->len > 0) {
                emit_inline_asm(ctx, sec, list_get(ins->labels, 0), ins);
            }
            break;
        
        case IROP_ADDR: {
            
            const char *lbl = (ins->labels && ins->labels->len>0) ? list_get(ins->labels,0) : "<addr>";
            AsmInstr* ai = calloc(1, sizeof(AsmInstr));
            ai->op = strdup("; ADDR");
            ai->args = make_list();
            ai->ssa = instr_to_ssa_str(ins);
            list_push(sec->asminstrs, ai);
            break;
        }

        case IROP_STORE: {
            AsmInstr* ai = calloc(1, sizeof(AsmInstr));
            ai->op = strdup("; STORE");
            ai->args = make_list();
            ai->ssa = instr_to_ssa_str(ins);
            list_push(sec->asminstrs, ai);
            break;
        }
            
        default: {
            AsmInstr* ai = calloc(1, sizeof(AsmInstr));
            ai->op = strdup("; UNIMPL");
            ai->args = make_list();
            ai->ssa = instr_to_ssa_str(ins);
            list_push(sec->asminstrs, ai);
            break;
        }
    }
}
