/* c51gen.c - C51 (8051) 汇编代码生成器
 * 使用线性寄存器分配
 */

#include "ssa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>

/* ============================================================
 * C51 寄存器和内存管理
 * ============================================================ */

// C51 寄存器定义
typedef enum {
    REG_A,      // 累加器
    REG_B,      // B寄存器
    REG_R0, REG_R1, REG_R2, REG_R3,  // 通用寄存器
    REG_R4, REG_R5, REG_R6, REG_R7,
    REG_DPTR,   // 数据指针 (16位)
    REG_SP,     // 堆栈指针
    REG_C,      // 进位标志
    REG_NONE
} C51Reg;

// 寄存器信息
typedef struct {
    C51Reg reg;
    const char *name;
    bool is_free;
    bool is_8bit;   // 8位寄存器
    bool is_16bit;  // 16位寄存器
} RegInfo;

// 寄存器表
static RegInfo reg_table[] = {
    {REG_A,     "A",     true,  true,  false},
    {REG_B,     "B",     true,  true,  false},
    {REG_R0,    "R0",    true,  true,  false},
    {REG_R1,    "R1",    true,  true,  false},
    {REG_R2,    "R2",    true,  true,  false},
    {REG_R3,    "R3",    true,  true,  false},
    {REG_R4,    "R4",    true,  true,  false},
    {REG_R5,    "R5",    true,  true,  false},
    {REG_R6,    "R6",    true,  true,  false},
    {REG_R7,    "R7",    true,  true,  false},
    {REG_DPTR,  "DPTR",  true,  false, true},
    {REG_SP,    "SP",    true,  true,  false},
    {REG_NONE,  NULL,    false, false, false}
};

// 栈帧信息
typedef struct {
    int local_size;     // 局部变量大小
    int param_size;     // 参数大小
    int reg_spill_base; // 寄存器溢出基址
} StackFrame;

// 代码生成上下文
typedef struct {
    FILE *fp;           // 输出文件
    Func *cur_func;     // 当前函数
    StackFrame frame;   // 栈帧信息
    
    // 虚拟寄存器到物理寄存器/内存的映射
    // ValueName -> C51Reg (正数) 或 内存偏移 (负数)
    int *vreg_map;
    int vreg_map_size;
    
    // 临时变量计数
    int temp_count;
    int label_count;
} C51Gen;

/* 前向声明 */
static bool is_imm_value(C51Gen *gen, ValueName vreg, int64_t val);
static void scan_const_values(Func *f);

static void* gen_alloc(size_t size) {
    void *p = malloc(size);
    if (!p) { fprintf(stderr, "C51Gen: out of memory\n"); exit(1); }
    memset(p, 0, size);
    return p;
}

/* ============================================================
 * 线性寄存器分配
 * ============================================================ */

static void reset_regs(C51Gen *gen) {
    for (int i = 0; reg_table[i].name; i++) {
        if (reg_table[i].reg != REG_A && reg_table[i].reg != REG_SP) {
            reg_table[i].is_free = true;
        }
    }
}

static C51Reg alloc_reg(C51Gen *gen) {
    // 优先分配 R0-R7 (避开 A，因为 A 是累加器)
    for (int i = 2; reg_table[i].name; i++) {  // 从 R0 开始
        if (reg_table[i].is_free && reg_table[i].is_8bit) {
            reg_table[i].is_free = false;
            return reg_table[i].reg;
        }
    }
    return REG_NONE;  // 需要溢出到内存
}

static void free_reg(C51Gen *gen, C51Reg reg) {
    for (int i = 0; reg_table[i].name; i++) {
        if (reg_table[i].reg == reg) {
            reg_table[i].is_free = true;
            return;
        }
    }
}

static const char* reg_name(C51Reg reg) {
    for (int i = 0; reg_table[i].name; i++) {
        if (reg_table[i].reg == reg) return reg_table[i].name;
    }
    return "?";
}

// 线性寄存器分配：为每个虚拟寄存器分配物理寄存器或栈位置
static void linear_regalloc(C51Gen *gen, Func *f) {
    // 统计最大虚拟寄存器号
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
    
    // 简单策略：前8个虚拟寄存器分配到 R0-R7，其余溢出到内存
    int spill_offset = 0;
    for (int i = 1; i <= max_vreg; i++) {
        if (i <= 8) {
            gen->vreg_map[i] = REG_R0 + (i - 1);  // 映射到 R0-R7
        } else {
            gen->vreg_map[i] = -(gen->frame.reg_spill_base + spill_offset);
            spill_offset += 1;
        }
    }
}

// 获取虚拟寄存器的存储位置描述
static void get_location(C51Gen *gen, ValueName vreg, char *buf, size_t buf_size) {
    if (vreg < 0 || vreg >= gen->vreg_map_size) {
        snprintf(buf, buf_size, "#ERR");
        return;
    }
    
    int loc = gen->vreg_map[vreg];
    if (loc >= 0) {
        // 物理寄存器
        snprintf(buf, buf_size, "%s", reg_name((C51Reg)loc));
    } else {
        // 内存溢出 (使用内部 RAM)
        snprintf(buf, buf_size, "0x%02X", 0x20 + (-loc));  // 从 IDATA 0x20 开始
    }
}

/* ============================================================
 * 汇编代码生成辅助函数
 * ============================================================ */

static void emit(C51Gen *gen, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(gen->fp, fmt, args);
    va_end(args);
    fprintf(gen->fp, "\n");
}

static void emit_label(C51Gen *gen, const char *name) {
    fprintf(gen->fp, "%s:\n", name);
}

static void emit_comment(C51Gen *gen, const char *fmt, ...) {
    fprintf(gen->fp, "; ");
    va_list args;
    va_start(args, fmt);
    vfprintf(gen->fp, fmt, args);
    va_end(args);
    fprintf(gen->fp, "\n");
}

// 生成唯一的标签
static void c51_make_label(C51Gen *gen, char *buf, size_t size, const char *prefix) {
    snprintf(buf, size, "L_%s_%d", prefix, gen->label_count++);
}

/* ============================================================
 * 指令生成
 * ============================================================ */

// 立即数优化：MOV A, #0 -> CLR A
static bool try_optimize_load_imm(char *buf, size_t size, int val) {
    if (val == 0) {
        snprintf(buf, size, "    CLR A");
        return true;
    }
    if (val == 1) {
        snprintf(buf, size, "    MOV A, #1");
        return true;
    }
    return false;
}

// 加载立即数到 A (基础版本)
static void emit_load_imm(C51Gen *gen, int64_t val) {
    emit(gen, "    MOV A, #0x%02X", (int)(val & 0xFF));
    if (val > 255 || val < -128) {
        // 16位值，需要扩展
        emit(gen, "    MOV B, #0x%02X", (int)((val >> 8) & 0xFF));
    }
}

// 优化的立即数加载：MOV A,#0 -> CLR A
static void emit_load_imm_opt(C51Gen *gen, int64_t val) {
    char buf[64];
    if (try_optimize_load_imm(buf, sizeof(buf), (int)val)) {
        fprintf(gen->fp, "%s\n", buf);
    } else {
        emit(gen, "    MOV A, #0x%02X", (int)(val & 0xFF));
        if (val > 255 || val < -128) {
            emit(gen, "    MOV B, #0x%02X", (int)((val >> 8) & 0xFF));
        }
    }
}

// 跟踪最后存储的位置用于消除冗余MOV
static ValueName last_stored_vreg = -1;

// 检查虚拟寄存器是否为特定立即数值
// 需要在函数生成前扫描常量定义
static int64_t *vreg_const_values = NULL;

// PHI copy 队列 - 需要在跳转前插入的MOV
// 由于不能修改SSA结构，我们在生成每个块前处理其PHI的copy

/* ============================================================
 * PHI 节点处理
 * ============================================================ */

typedef struct PhiCopy {
    ValueName src;      // 源值
    ValueName dest;     // PHI 目标
    Block *pred;        // 来自哪个前驱
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

static bool is_imm_value(C51Gen *gen, ValueName vreg, int64_t val) {
    if (vreg < 0 || vreg >= gen->vreg_map_size) return false;
    if (!vreg_const_values) return false;
    return vreg_const_values[vreg] == val;
}

// 检查指令是否是基本块的终止指令
static bool is_terminator(Instr *inst) {
    if (!inst) return false;
    return inst->op == IROP_JMP || inst->op == IROP_BR ||
           inst->op == IROP_RET || inst->op == IROP_CALL;
}

// 生成 PHI copy MOV 指令
static void emit_phi_copy(C51Gen *gen, ValueName src, ValueName dest) {
    char src_loc[32], dest_loc[32];
    get_location(gen, src, src_loc, sizeof(src_loc));
    get_location(gen, dest, dest_loc, sizeof(dest_loc));
    
    // 如果源和目标是同一位置，跳过
    if (strcmp(src_loc, dest_loc) == 0) return;
    
    // 生成: MOV dest, src
    // 8051不支持直接内存到内存，需要通过A
    if (src_loc[0] == '0' && dest_loc[0] == '0') {
        // 内存到内存
        emit(gen, "    MOV A, %s", src_loc);
        emit(gen, "    MOV %s, A", dest_loc);
    } else if (dest_loc[0] == 'A' || (dest_loc[0] == 'A' && dest_loc[1] == 0)) {
        // 目标是A
        emit(gen, "    MOV A, %s", src_loc);
    } else if (src_loc[0] == 'A' || (src_loc[0] == 'A' && src_loc[1] == 0)) {
        // 源是A
        emit(gen, "    MOV %s, A", dest_loc);
    } else {
        // 寄存器之间或混合
        emit(gen, "    MOV A, %s", src_loc);
        emit(gen, "    MOV %s, A", dest_loc);
    }
}

// 扫描函数的常量定义
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

// 加载虚拟寄存器到 A
static void emit_load_vreg(C51Gen *gen, ValueName vreg) {
    char loc[32];
    get_location(gen, vreg, loc, sizeof(loc));
    emit(gen, "    MOV A, %s", loc);
}

// 保存 A 到虚拟寄存器
static void emit_store_vreg(C51Gen *gen, ValueName vreg) {
    char loc[32];
    get_location(gen, vreg, loc, sizeof(loc));
    emit(gen, "    MOV %s, A", loc);
    last_stored_vreg = vreg;
}

// 二元运算
static void emit_binary_op(C51Gen *gen, IrOp op, ValueName dest, ValueName lhs, ValueName rhs) {
    // 检查是否可以优化: 如果左操作数刚被存储且目标相同，避免重复加载
    if (last_stored_vreg == lhs) {
        // A 中已经包含 lhs 的值
    } else {
        emit_load_vreg(gen, lhs);
    }
    
    char rhs_loc[32];
    get_location(gen, rhs, rhs_loc, sizeof(rhs_loc));
    
    switch (op) {
    case IROP_ADD:
        emit(gen, "    ADD A, %s", rhs_loc);
        break;
    case IROP_SUB:
        emit(gen, "    CLR C");
        emit(gen, "    SUBB A, %s", rhs_loc);
        break;
    case IROP_MUL:
        // 8051 MUL AB: A * B -> BA
        emit(gen, "    MOV B, %s", rhs_loc);
        emit(gen, "    MUL AB");
        break;
    case IROP_DIV:
        emit(gen, "    MOV B, %s", rhs_loc);
        emit(gen, "    DIV AB");
        break;
    case IROP_AND:
        emit(gen, "    ANL A, %s", rhs_loc);
        break;
    case IROP_OR:
        emit(gen, "    ORL A, %s", rhs_loc);
        break;
    case IROP_XOR:
        emit(gen, "    XRL A, %s", rhs_loc);
        break;
    default:
        emit_comment(gen, "TODO: op %d", op);
        break;
    }
    
    // 保存结果
    emit_store_vreg(gen, dest);
}

// 一元运算
static void emit_unary_op(C51Gen *gen, IrOp op, ValueName dest, ValueName src) {
    emit_load_vreg(gen, src);
    
    switch (op) {
    case IROP_NEG:
        emit(gen, "    CPL A");
        emit(gen, "    INC A");
        break;
    case IROP_NOT:
        emit(gen, "    CPL A");
        break;
    case IROP_LNOT: {
        // !A = (A == 0) ? 1 : 0
        char label_zero[32], label_end[32];
        snprintf(label_zero, sizeof(label_zero), "L_lnot_zero_%d", gen->label_count);
        snprintf(label_end, sizeof(label_end), "L_lnot_end_%d", gen->label_count);
        emit(gen, "    JNZ %s", label_zero);
        emit(gen, "    MOV A, #1");
        emit(gen, "    SJMP %s", label_end);
        emit_label(gen, label_zero);
        emit(gen, "    MOV A, #0");
        emit_label(gen, label_end);
        gen->label_count++;
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
    char rhs_loc[32];
    get_location(gen, rhs, rhs_loc, sizeof(rhs_loc));
    
    emit(gen, "    CLR C");
    emit(gen, "    SUBB A, %s", rhs_loc);
    
    const char *jump_instr = NULL;
    switch (op) {
    case IROP_EQ: jump_instr = "JZ"; break;
    case IROP_NE: jump_instr = "JNZ"; break;
    case IROP_LT: jump_instr = "JC"; break;  // A < rhs
    case IROP_GT: jump_instr = "JNC"; break; // A > rhs (需要进一步检查)
    default: break;
    }
    
    if (jump_instr) {
        emit(gen, "    %s %s", jump_instr, label_true);
        emit(gen, "    MOV A, #0");      // false
        emit(gen, "    SJMP %s", label_end);
        emit_label(gen, label_true);
        emit(gen, "    MOV A, #1");      // true
        emit_label(gen, label_end);
    }
    
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
        // 参数通过寄存器或栈传递
        // 简化：假设前几个参数在 R0-R3
        int param_idx = 0;
        if (inst->dest <= 4) {
            emit(gen, "    MOV R%d, A", inst->dest - 1);
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
        // 使用优化的跳转选择 (目前简化为长跳转)
        emit(gen, "    LJMP %s", label);
        break;
    }
    
    case IROP_BR: {
        ValueName cond = *(ValueName*)list_get(inst->args, 0);
        char *label_true = list_get(inst->labels, 0);
        char *label_false = list_get(inst->labels, 1);
        
        emit_load_vreg(gen, cond);
        emit(gen, "    JNZ %s", label_true);
        emit(gen, "    LJMP %s", label_false);
        break;
    }
    
    case IROP_RET:
        if (inst->args->len > 0) {
            ValueName val = *(ValueName*)list_get(inst->args, 0);
            emit_load_vreg(gen, val);
        }
        emit(gen, "    RET");
        break;
        
    case IROP_CALL: {
        char *fname = list_get(inst->labels, 0);
        emit(gen, "    LCALL %s", fname);
        // 返回值在 A 中
        if (inst->dest > 0) {
            emit_store_vreg(gen, inst->dest);
        }
        break;
    }
    
    case IROP_PHI:
        // PHI 节点在代码生成前应该被简化或处理
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

// 检查函数是否已有返回指令
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
    gen->frame.param_size = f->params->len * 2;  // 每个参数2字节
    gen->frame.reg_spill_base = 0;
    gen->label_count = 0;
    last_stored_vreg = -1;
    
    // 扫描常量值用于优化
    scan_const_values(f);
    
    // 进行寄存器分配
    linear_regalloc(gen, f);
    
    // 收集所有 PHI copy 信息
    // 对于每个块，收集需要在该块末尾插入的PHI copies
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        // 遍历该块的所有 PHI 节点
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            // PHI 参数: [v1, block1], [v2, block2], ...
            for (int i = 0; i < phi->args->len && i < phi->labels->len; i++) {
                ValueName *src = list_get(phi->args, i);
                char *pred_label = list_get(phi->labels, i);
                // 查找前驱块
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
    emit(gen, "; =======================================");
    emit(gen, "; Function: %s", f->name);
    emit(gen, "; =======================================");
    emit(gen, "    PUBLIC %s", f->name);
    emit(gen, "%s PROC", f->name);
    
    // 普通函数不保存寄存器，由程序员自行管理
    // 只有中断服务程序(ISR)才需要保存 ACC, B, R0-R3
    
    // 生成基本块代码
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        
        // 块标签 (跳过 entry)
        if (blk != f->entry) {
            emit(gen, "block%u:", blk->id);
        }
        
        // 生成 PHI 指令 (仅注释，实际处理在跳转前)
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            emit_comment(gen, "PHI: v%d = phi ...", phi->dest);
        }
        
        // 生成普通指令
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            
            // 在跳转/返回/分支指令前插入该块的PHI copies
            if (inst->op == IROP_JMP || inst->op == IROP_BR ||
                inst->op == IROP_RET || inst->op == IROP_CALL) {
                // 查找并生成该块作为前驱的PHI copies
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
        
        // 如果块没有终止指令（如fall-through），也要处理PHI copies
        // 检查是否是fall-through到下一个块
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
    
    // 清理PHI copies
    phi_copies_clear();
    
    // 函数出口 - 只在函数没有显式返回时生成
    if (!func_has_ret(f)) {
        emit(gen, "%s_exit:", f->name);
        emit(gen, "    RET");
    }
    emit(gen, "%s ENDP", f->name);
    emit(gen, "");
    
    free(gen->vreg_map);
    gen->vreg_map = NULL;
}

/* ============================================================
 * 公共 API
 * ============================================================ */

void c51_gen(FILE *fp, SSAUnit *unit) {
    C51Gen gen = {0};
    gen.fp = fp;
    
    // 文件头
    fprintf(fp, "; C51 Assembly Generated from SSA IR\n");
    fprintf(fp, "; Linear Register Allocation\n");
    fprintf(fp, "\n");
    fprintf(fp, "    ORG 0000H\n");
    fprintf(fp, "    LJMP main\n");
    fprintf(fp, "\n");
    fprintf(fp, "; Internal RAM for spilled registers\n");
    fprintf(fp, "    DSEG AT 20H\n");
    fprintf(fp, "spill_area: DS 32\n");
    fprintf(fp, "\n");
    fprintf(fp, "    CSEG\n");
    fprintf(fp, "\n");
    
    // 生成每个函数
    for (Iter it = list_iter(unit->funcs); !iter_end(it);) {
        Func *f = iter_next(&it);
        emit_function(&gen, f);
    }
    
    // 文件尾
    fprintf(fp, "\n");
    fprintf(fp, "    END\n");
}

/* ============================================================
 * 汇编层优化（参考 Keil C51）
 * ============================================================ */

// 汇编指令结构
typedef struct AsmInstr {
    char *text;
    struct AsmInstr *next;
} AsmInstr;

// 窥孔优化：消除冗余 MOV
static bool opt_peephole_mov(AsmInstr **instrs) {
    bool changed = false;
    // 模式: MOV A, Rx; MOV Ry, A -> 如果 Ry == Rx，删除第二条
    // 模式: MOV A, #0 -> CLR A
    return changed;
}

// 跳转优化：LJMP -> AJMP/SJMP
static void opt_select_jump(char *buf, size_t size, const char *target, int offset) {
    // 如果在短跳转范围内 (-128~+127)
    if (offset >= -128 && offset <= 127) {
        snprintf(buf, size, "    SJMP %s", target);
    } else {
        snprintf(buf, size, "    LJMP %s", target);
    }
}

// 二元运算优化：使用 INC/DEC 代替 ADD/SUB #1
static bool try_optimize_inc_dec(C51Gen *gen, IrOp op, ValueName dest, ValueName src, int64_t imm) {
    if (imm != 1 && imm != -1) return false;
    
    char src_loc[32];
    get_location(gen, src, src_loc, sizeof(src_loc));
    
    if (op == IROP_ADD && imm == 1) {
        // 递增
        if (strcmp(src_loc, "A") == 0) {
            emit(gen, "    INC A");
        } else if (src_loc[0] == 'R' && src_loc[1] >= '0' && src_loc[1] <= '7') {
            emit(gen, "    INC %s", src_loc);
        }
        emit_store_vreg(gen, dest);
        return true;
    }
    if (op == IROP_SUB && imm == 1) {
        // 递减
        if (strcmp(src_loc, "A") == 0) {
            emit(gen, "    DEC A");
        } else if (src_loc[0] == 'R' && src_loc[1] >= '0' && src_loc[1] <= '7') {
            emit(gen, "    DEC %s", src_loc);
        }
        emit_store_vreg(gen, dest);
        return true;
    }
    return false;
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
#endif
