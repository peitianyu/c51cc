#ifndef C51_ISEL_H
#define C51_ISEL_H

#include "c51_gen.h"
#include "../obj.h"

/* C51参数寄存器约定 */
/* char: R7→R5→R3→R2→R4→R6 */
/* int:  R6:R7→R4:R5→R2:R3 (大端) */
extern const int param_regs_char[];
extern const int param_regs_int_h[];
extern const int param_regs_int_l[];

/* 辅助函数：将整数键转换为字符串 */
char* int_to_key(int n);

/* 指令选择上下文 */
typedef struct ISelContext {
    C51GenContext* ctx;
    Section* sec;
    int current_block_id;
    
    /* 寄存器分配状态 */
    bool reg_busy[8];       /* R0-R7 占用状态 */
    ValueName reg_val[8];   /* 每个寄存器存储的值 */
    
    /* 累加器状态 */
    bool acc_busy;
    ValueName acc_val;
    
    /* 标签计数器 */
    int label_counter;
} ISelContext;

/* 指令选择主入口 */
void isel_function(C51GenContext* ctx, Func* func);

/* 基本块指令选择 */
void isel_block(ISelContext* isel, Block* block);

/* 单条指令选择 */
void isel_instr(ISelContext* isel, Instr* ins, Instr* next);

/* 辅助函数：发射汇编指令 */
void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2, const char* ssa);

/* 辅助函数：生成标签 */
char* isel_new_label(ISelContext* isel, const char* prefix);

/* 寄存器分配查询 */
int isel_get_value_reg(ISelContext* isel, ValueName val);
const char* isel_reg_name(int reg);
const char* isel_get_value_reg_at(ISelContext* isel, ValueName val, int offset);
const char* isel_get_lo_reg(ISelContext* isel, ValueName val);
const char* isel_get_hi_reg(ISelContext* isel, ValueName val);

/* 值位置管理 */
void isel_ensure_in_acc(ISelContext* isel, ValueName val);
bool isel_can_keep_in_acc(ISelContext* isel, Instr* ins, Instr* next);

/* SSA指令转字符串（用于注释） */
char* instr_to_ssa_str(Instr* ins);

#endif
