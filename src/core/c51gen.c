/* c51gen.c - C51 (8051) 汇编代码生成器
 * 使用线性寄存器分配和 C51Buffer 存储指令
 */

#include "ssa.h"
#include "c51asm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>

/* ============================================================
 * C51 寄存器和内存管理
 * ============================================================ */

// 寄存器信息 (直接使用 C51Reg)
typedef struct {
    C51Reg reg;
    const char *name;
    bool is_free;
    bool is_8bit;
    bool is_16bit;
} RegInfo;

static RegInfo reg_table[] = {
    {C51_REG_A,     "A",     true,  true,  false},
    {C51_REG_B,     "B",     true,  true,  false},
    {C51_REG_R0,    "R0",    true,  true,  false},
    {C51_REG_R1,    "R1",    true,  true,  false},
    {C51_REG_R2,    "R2",    true,  true,  false},
    {C51_REG_R3,    "R3",    true,  true,  false},
    {C51_REG_R4,    "R4",    true,  true,  false},
    {C51_REG_R5,    "R5",    true,  true,  false},
    {C51_REG_R6,    "R6",    true,  true,  false},
    {C51_REG_R7,    "R7",    true,  true,  false},
    {C51_REG_DPTR,  "DPTR",  true,  false, true},
    {C51_REG_SP,    "SP",    true,  true,  false},
    {C51_REG_C,     "C",     true,  true,  false},
    {-1,            NULL,    false, false, false}
};

// 栈帧信息
typedef struct {
    int local_size;
    int param_size;
    int reg_spill_base;
} StackFrame;

// 代码生成上下文
typedef struct {
    C51Buffer *buf;
    Func *cur_func;
    StackFrame frame;
    int *vreg_map;
    int vreg_map_size;
    int temp_count;
    int label_count;
} C51Gen;

static void* gen_alloc(size_t size) {
    void *p = malloc(size);
    if (!p) { fprintf(stderr, "C51Gen: out of memory\n"); exit(1); }
    memset(p, 0, size);
    return p;
}

static void reset_regs(C51Gen *gen) {
    for (int i = 0; reg_table[i].name; i++) {
        if (reg_table[i].reg != C51_REG_A && reg_table[i].reg != C51_REG_SP) {
            reg_table[i].is_free = true;
        }
    }
}

static C51Reg alloc_reg(C51Gen *gen) {
    for (int i = 2; reg_table[i].name; i++) {
        if (reg_table[i].is_free && reg_table[i].is_8bit) {
            reg_table[i].is_free = false;
            return reg_table[i].reg;
        }
    }
    return -1;
}

static void free_reg(C51Gen *gen, C51Reg reg) {
    for (int i = 0; reg_table[i].name; i++) {
        if (reg_table[i].reg == reg) {
            reg_table[i].is_free = true;
            return;
        }
    }
}

// 线性寄存器分配
static void linear_regalloc(C51Gen *gen, Func *f) {
    int max_vreg = 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->dest > max_vreg) max_vreg = inst->dest;
        }
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            if (phi->dest > max_vreg) max_vreg = phi->dest;
        }
    }
    
    gen->vreg_map_size = max_vreg + 1;
    gen->vreg_map = gen_alloc(sizeof(int) * gen->vreg_map_size);
    
    int spill_offset = 0;
    for (int i = 1; i <= max_vreg; i++) {
        if (i <= 8) {
            gen->vreg_map[i] = C51_REG_R0 + (i - 1);
        } else {
            gen->vreg_map[i] = -(gen->frame.reg_spill_base + spill_offset);
            spill_offset += 1;
        }
    }
}

// 获取虚拟寄存器作为操作数
static C51Operand get_vreg_op(C51Gen *gen, ValueName vreg) {
    if (vreg < 0 || vreg >= gen->vreg_map_size) {
        return c51_direct(0x20);
    }
    
    int loc = gen->vreg_map[vreg];
    if (loc >= 0) {
        return c51_reg(loc);
    } else {
        return c51_direct(0x20 + (-loc));
    }
}

/* ============================================================
 * 指令生成辅助函数
 * ============================================================ */

static void emit_load_vreg(C51Gen *gen, ValueName vreg) {
    C51Operand src = get_vreg_op(gen, vreg);
    c51_emit_mov(gen->buf, c51_reg(C51_REG_A), src);
}

static void emit_store_vreg(C51Gen *gen, ValueName vreg) {
    C51Operand dst = get_vreg_op(gen, vreg);
    c51_emit_mov(gen->buf, dst, c51_reg(C51_REG_A));
}

static void emit_comment(C51Gen *gen, const char *fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    c51_emit_comment(gen->buf, "%s", buf);
}

static void emit_label(C51Gen *gen, const char *name) {
    c51_emit_label(gen->buf, name);
}

static void c51_make_label(C51Gen *gen, char *buf, size_t size, const char *prefix) {
    snprintf(buf, size, "L_%s_%d", prefix, gen->label_count++);
}

/* ============================================================
 * PHI 节点处理
 * ============================================================ */

typedef struct PhiCopy {
    ValueName src;
    ValueName dest;
    Block *pred;
    struct PhiCopy *next;
} PhiCopy;

static PhiCopy *phi_copies = NULL;

static void phi_copy_add(ValueName src, ValueName dest, Block *pred) {
    PhiCopy *copy = malloc(sizeof(PhiCopy));
    copy->src = src;
    copy->dest = dest;
    copy->pred = pred;
    copy->next = phi_copies;
    phi_copies = copy;
}

static void phi_copies_clear(void) {
    while (phi_copies) {
        PhiCopy *next = phi_copies->next;
        free(phi_copies);
        phi_copies = next;
    }
    phi_copies = NULL;
}

static bool is_terminator(Instr *inst) {
    if (!inst) return false;
    return inst->op == IROP_JMP || inst->op == IROP_BR ||
           inst->op == IROP_RET || inst->op == IROP_CALL;
}

// 生成 PHI copy MOV 指令
static void emit_phi_copy(C51Gen *gen, ValueName src, ValueName dest) {
    C51Operand src_op = get_vreg_op(gen, src);
    C51Operand dst_op = get_vreg_op(gen, dest);
    
    // 如果源和目标是同一位置，跳过
    if (src_op.type == dst_op.type && src_op.reg == dst_op.reg &&
        (src_op.type == C51_OP_REG || 
         (src_op.type == C51_OP_DIRECT && src_op.imm == dst_op.imm))) {
        return;
    }
    
    // 8051不支持直接内存到内存，需要通过A
    if (src_op.type == C51_OP_DIRECT && dst_op.type == C51_OP_DIRECT) {
        c51_emit_mov(gen->buf, c51_reg(C51_REG_A), src_op);
        c51_emit_mov(gen->buf, dst_op, c51_reg(C51_REG_A));
    } else if (dst_op.type == C51_OP_REG && dst_op.reg == C51_REG_A) {
        c51_emit_mov(gen->buf, c51_reg(C51_REG_A), src_op);
    } else if (src_op.type == C51_OP_REG && src_op.reg == C51_REG_A) {
        c51_emit_mov(gen->buf, dst_op, c51_reg(C51_REG_A));
    } else {
        c51_emit_mov(gen->buf, c51_reg(C51_REG_A), src_op);
        c51_emit_mov(gen->buf, dst_op, c51_reg(C51_REG_A));
    }
}

static int64_t *vreg_const_values = NULL;

static void scan_const_values(Func *f) {
    if (vreg_const_values) free(vreg_const_values);
    int max_vreg = 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->dest > max_vreg) max_vreg = inst->dest;
        }
    }
    vreg_const_values = calloc(max_vreg + 1, sizeof(int64_t));
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->op == IROP_CONST) {
                vreg_const_values[inst->dest] = inst->imm.ival;
            }
        }
    }
}

/* ============================================================
 * 指令生成
 * ============================================================ */

// 加载立即数到 A
static void emit_load_imm(C51Gen *gen, int64_t val) {
    c51_emit_mov(gen->buf, c51_reg(C51_REG_A), c51_imm((int)val & 0xFF));
    if (val > 255 || val < -128) {
        c51_emit_mov(gen->buf, c51_reg(C51_REG_B), c51_imm((int)(val >> 8) & 0xFF));
    }
}

// 优化的立即数加载
static void emit_load_imm_opt(C51Gen *gen, int64_t val) {
    if (val == 0) {
        c51_emit_unary(gen->buf, C51_CLR, c51_reg(C51_REG_A));
    } else {
        c51_emit_mov(gen->buf, c51_reg(C51_REG_A), c51_imm((int)val & 0xFF));
    }
    if (val > 255 || val < -128) {
        c51_emit_mov(gen->buf, c51_reg(C51_REG_B), c51_imm((int)(val >> 8) & 0xFF));
    }
}

// 二元运算
static void emit_binary_op(C51Gen *gen, IrOp op, ValueName dest, ValueName lhs, ValueName rhs) {
    emit_load_vreg(gen, lhs);
    
    C51Operand rhs_op = get_vreg_op(gen, rhs);
    
    switch (op) {
    case IROP_ADD:
        c51_emit_alu(gen->buf, C51_ADD, c51_reg(C51_REG_A), rhs_op);
        break;
    case IROP_SUB:
        c51_emit_unary(gen->buf, C51_CLR, c51_reg(C51_REG_C));
        c51_emit_alu(gen->buf, C51_SUBB, c51_reg(C51_REG_A), rhs_op);
        break;
    case IROP_MUL:
        c51_emit_mov(gen->buf, c51_reg(C51_REG_B), rhs_op);
        c51_emit(gen->buf, C51_MUL, c51_none(), c51_none(), NULL);
        break;
    case IROP_DIV:
        c51_emit_mov(gen->buf, c51_reg(C51_REG_B), rhs_op);
        c51_emit(gen->buf, C51_DIV, c51_none(), c51_none(), NULL);
        break;
    case IROP_AND:
        c51_emit_alu(gen->buf, C51_ANL, c51_reg(C51_REG_A), rhs_op);
        break;
    case IROP_OR:
        c51_emit_alu(gen->buf, C51_ORL, c51_reg(C51_REG_A), rhs_op);
        break;
    case IROP_XOR:
        c51_emit_alu(gen->buf, C51_XRL, c51_reg(C51_REG_A), rhs_op);
        break;
    default:
        emit_comment(gen, "TODO: op %d", op);
        break;
    }
    
    emit_store_vreg(gen, dest);
}

// 一元运算
static void emit_unary_op(C51Gen *gen, IrOp op, ValueName dest, ValueName src) {
    emit_load_vreg(gen, src);
    
    switch (op) {
    case IROP_NEG:
        c51_emit_unary(gen->buf, C51_CPL, c51_reg(C51_REG_A));
        c51_emit_unary(gen->buf, C51_INC, c51_reg(C51_REG_A));
        break;
    case IROP_NOT:
        c51_emit_unary(gen->buf, C51_CPL, c51_reg(C51_REG_A));
        break;
    case IROP_LNOT: {
        char label_zero[32], label_end[32];
        c51_make_label(gen, label_zero, sizeof(label_zero), "lnot_zero");
        c51_make_label(gen, label_end, sizeof(label_end), "lnot_end");
        c51_emit_branch(gen->buf, C51_JNZ, c51_reg(C51_REG_A), label_zero);
        c51_emit_mov(gen->buf, c51_reg(C51_REG_A), c51_imm(1));
        c51_emit_jump(gen->buf, C51_SJMP, label_end);
        emit_label(gen, label_zero);
        c51_emit_mov(gen->buf, c51_reg(C51_REG_A), c51_imm(0));
        emit_label(gen, label_end);
        break;
    }
    default:
        emit_comment(gen, "TODO: unary op %d", op);
        break;
    }
    
    emit_store_vreg(gen, dest);
}

// 比较运算
static void emit_compare(C51Gen *gen, IrOp op, ValueName dest, ValueName lhs, ValueName rhs) {
    char label_true[32], label_end[32];
    c51_make_label(gen, label_true, sizeof(label_true), "cmp_true");
    c51_make_label(gen, label_end, sizeof(label_end), "cmp_end");
    
    emit_load_vreg(gen, lhs);
    C51Operand rhs_op = get_vreg_op(gen, rhs);
    
    c51_emit_unary(gen->buf, C51_CLR, c51_reg(C51_REG_C));
    c51_emit_alu(gen->buf, C51_SUBB, c51_reg(C51_REG_A), rhs_op);
    
    C51Op jump_op = C51_JZ;
    switch (op) {
    case IROP_EQ: jump_op = C51_JZ; break;
    case IROP_NE: jump_op = C51_JNZ; break;
    case IROP_LT: jump_op = C51_JC; break;
    case IROP_GT: jump_op = C51_JNC; break;
    default: break;
    }
    
    c51_emit_branch(gen->buf, jump_op, c51_reg(C51_REG_A), label_true);
    c51_emit_mov(gen->buf, c51_reg(C51_REG_A), c51_imm(0));
    c51_emit_jump(gen->buf, C51_SJMP, label_end);
    emit_label(gen, label_true);
    c51_emit_mov(gen->buf, c51_reg(C51_REG_A), c51_imm(1));
    emit_label(gen, label_end);
    
    emit_store_vreg(gen, dest);
}

// 生成单条指令
static void emit_instr(C51Gen *gen, Instr *inst) {
    switch (inst->op) {
    case IROP_NOP:
        break;
        
    case IROP_CONST:
        emit_load_imm_opt(gen, inst->imm.ival);
        emit_store_vreg(gen, inst->dest);
        break;
        
    case IROP_PARAM: {
        if (inst->dest <= 4) {
            C51Reg dst_reg = C51_REG_R0 + (inst->dest - 1);
            c51_emit_mov(gen->buf, c51_reg(dst_reg), c51_reg(C51_REG_A));
        }
        break;
    }
    
    case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV:
    case IROP_AND: case IROP_OR: case IROP_XOR:
        if (inst->args->len >= 2) {
            ValueName lhs = *(ValueName*)list_get(inst->args, 0);
            ValueName rhs = *(ValueName*)list_get(inst->args, 1);
            emit_binary_op(gen, inst->op, inst->dest, lhs, rhs);
        }
        break;
        
    case IROP_NEG: case IROP_NOT: case IROP_LNOT:
        if (inst->args->len >= 1) {
            ValueName src = *(ValueName*)list_get(inst->args, 0);
            emit_unary_op(gen, inst->op, inst->dest, src);
        }
        break;
        
    case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE:
        if (inst->args->len >= 2) {
            ValueName lhs = *(ValueName*)list_get(inst->args, 0);
            ValueName rhs = *(ValueName*)list_get(inst->args, 1);
            emit_compare(gen, inst->op, inst->dest, lhs, rhs);
        }
        break;
        
    case IROP_JMP: {
        char *label = list_get(inst->labels, 0);
        c51_emit_jump(gen->buf, C51_LJMP, label);
        break;
    }
    
    case IROP_BR: {
        ValueName cond = *(ValueName*)list_get(inst->args, 0);
        char *label_true = list_get(inst->labels, 0);
        char *label_false = list_get(inst->labels, 1);
        
        emit_load_vreg(gen, cond);
        c51_emit_branch(gen->buf, C51_JNZ, c51_reg(C51_REG_A), label_true);
        c51_emit_jump(gen->buf, C51_LJMP, label_false);
        break;
    }
    
    case IROP_RET:
        if (inst->args->len > 0) {
            ValueName val = *(ValueName*)list_get(inst->args, 0);
            emit_load_vreg(gen, val);
        }
        c51_emit_ret(gen->buf);
        break;
        
    case IROP_CALL: {
        char *fname = list_get(inst->labels, 0);
        c51_emit_call(gen->buf, fname, true);
        if (inst->dest > 0) {
            emit_store_vreg(gen, inst->dest);
        }
        break;
    }
    
    case IROP_PHI:
        emit_comment(gen, "PHI: v%d", inst->dest);
        break;
        
    default:
        emit_comment(gen, "TODO: IROP_%d", inst->op);
        break;
    }
}

/* ============================================================
 * 函数生成
 * ============================================================ */

static bool func_has_ret(Func *f) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->op == IROP_RET) return true;
        }
    }
    return false;
}

static void emit_function(C51Gen *gen, Func *f) {
    gen->cur_func = f;
    gen->frame.local_size = 0;
    gen->frame.param_size = f->params->len * 2;
    gen->frame.reg_spill_base = 0;
    gen->label_count = 0;
    
    scan_const_values(f);
    linear_regalloc(gen, f);
    
    // 收集 PHI copy 信息
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            for (int i = 0; i < phi->args->len && i < phi->labels->len; i++) {
                ValueName *src = list_get(phi->args, i);
                char *pred_label = list_get(phi->labels, i);
                for (Iter kt = list_iter(f->blocks); !iter_end(kt);) {
                    Block *pred = iter_next(&kt);
                    char label_buf[32];
                    if (pred == f->entry) {
                        snprintf(label_buf, sizeof(label_buf), "%s_entry", f->name);
                    } else {
                        snprintf(label_buf, sizeof(label_buf), "block%u", pred->id);
                    }
                    if (strcmp(pred_label, label_buf) == 0) {
                        phi_copy_add(*src, phi->dest, pred);
                        break;
                    }
                }
            }
        }
    }
    
    // 函数头
    emit_comment(gen, "=======================================");
    emit_comment(gen, "Function: %s", f->name);
    emit_comment(gen, "=======================================");
    c51_emit_directive(gen->buf, "PUBLIC");
    c51_emit_directive(gen->buf, f->name);
    
    char proc_label[64];
    snprintf(proc_label, sizeof(proc_label), "%s PROC", f->name);
    c51_emit_directive(gen->buf, proc_label);
    
    // 生成基本块代码
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        
        if (blk != f->entry) {
            char block_label[32];
            snprintf(block_label, sizeof(block_label), "block%u", blk->id);
            emit_label(gen, block_label);
        }
        
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            emit_comment(gen, "PHI: v%d = phi ...", phi->dest);
        }
        
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            
            if (inst->op == IROP_JMP || inst->op == IROP_BR ||
                inst->op == IROP_RET || inst->op == IROP_CALL) {
                PhiCopy *copy = phi_copies;
                while (copy) {
                    if (copy->pred == blk) {
                        emit_phi_copy(gen, copy->src, copy->dest);
                    }
                    copy = copy->next;
                }
            }
            
            emit_instr(gen, inst);
        }
        
        if (blk->instrs->len == 0 || !is_terminator(list_get(blk->instrs, blk->instrs->len - 1))) {
            PhiCopy *copy = phi_copies;
            while (copy) {
                if (copy->pred == blk) {
                    emit_phi_copy(gen, copy->src, copy->dest);
                }
                copy = copy->next;
            }
        }
    }
    
    phi_copies_clear();
    
    if (!func_has_ret(f)) {
        char exit_label[64];
        snprintf(exit_label, sizeof(exit_label), "%s_exit", f->name);
        emit_label(gen, exit_label);
        c51_emit_ret(gen->buf);
    }
    
    char endp_label[64];
    snprintf(endp_label, sizeof(endp_label), "%s ENDP", f->name);
    c51_emit_directive(gen->buf, endp_label);
    c51_emit_directive(gen->buf, "");
    
    free(gen->vreg_map);
    gen->vreg_map = NULL;
}

/* ============================================================
 * 公共 API
 * ============================================================ */

void c51_gen(FILE *fp, SSAUnit *unit) {
    C51Buffer *buf = c51_buffer_create();
    c51_buffer_set_base(buf, 0x0000);
    
    C51Gen gen = {0};
    gen.buf = buf;
    
    // 文件头
    c51_emit_comment(buf, "C51 Assembly Generated from SSA IR");
    c51_emit_comment(buf, "Linear Register Allocation");
    c51_emit_directive(buf, "");
    c51_emit_directive(buf, "ORG 0000H");
    c51_emit_jump(buf, C51_LJMP, "main");
    c51_emit_directive(buf, "");
    c51_emit_comment(buf, "Internal RAM for spilled registers");
    c51_emit_directive(buf, "DSEG AT 20H");
    c51_emit_directive(buf, "spill_area: DS 32");
    c51_emit_directive(buf, "");
    c51_emit_directive(buf, "CSEG");
    c51_emit_directive(buf, "");
    
    // 生成每个函数
    for (Iter it = list_iter(unit->funcs); !iter_end(it);) {
        Func *f = iter_next(&it);
        emit_function(&gen, f);
    }
    
    // 优化
    c51_optimize_jumps(buf);
    
    // 输出
    c51_print_asm(buf, fp);
    
    c51_buffer_free(buf);
}

/* ============================================================
 * 测试代码
 * ============================================================ */

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

extern List *ctypes;
extern List *strings;
extern List *read_toplevels(void);
extern void set_current_filename(const char *filename);
extern char *ast_to_string(Ast *ast);

TEST(test, c51gen) {
    char infile[256];
    printf("file path for C51 code generation: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);
    
    SSABuild *b = ssa_build_create();
    List *toplevels = read_toplevels();
    
    printf("\n=== Parsing AST ===\n");
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("ast: %s\n", ast_to_string(v));
        ssa_convert_ast(b, v);
    }
    
    printf("\n=== SSA Output ===\n");
    ssa_print(stdout, b->unit);
    
    printf("\n=== C51 Assembly Output ===\n");
    c51_gen(stdout, b->unit);
    
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif  // MINITEST_IMPLEMENTATION
