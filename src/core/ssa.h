#ifndef __SSA_H__
#define __SSA_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "list.h"
#include "dict.h"
#include "cc.h"

typedef enum IrOp {
    IROP_NOP = 0,
    IROP_CONST,
    IROP_PARAM,
    // 算术
    IROP_ADD, IROP_SUB, IROP_MUL, IROP_DIV,
    IROP_MOD, IROP_NEG,
    // 位运算
    IROP_AND, IROP_OR, IROP_XOR, IROP_NOT,
    IROP_SHL, IROP_SHR,
    // 比较
    IROP_EQ, IROP_LT, IROP_GT, IROP_LE, IROP_GE, IROP_NE,
    // 逻辑
    IROP_LNOT, IROP_LAND, IROP_LOR,
    // 新增：C基础类型/指针操作（注：位域不单独设IROP，用位运算组合实现）
    IROP_TRUNC,         // 截断: (char)i
    IROP_ZEXT,          // 零扩展: unsigned提升
    IROP_SEXT,          // 符号扩展: signed提升
    IROP_BITCAST,       // 位重解释（float<->int）
    IROP_INTTOPTR,      // (void*)0x4000 - MMIO关键
    IROP_PTRTOINT,      // (uintptr_t)ptr
    IROP_OFFSET,        // ptr[idx] 地址计算
    IROP_SELECT,        // ?: 条件选择（替代部分PHI）
    // 内存
    IROP_ADDR,          // &var
    IROP_LOAD,          // *ptr
    IROP_STORE,         // *ptr = val
    // 控制流
    IROP_JMP, IROP_BR, IROP_CALL, IROP_RET, IROP_PHI,

    // 内联汇编（来自 __asm__("..."); 语句）
    IROP_ASM,
} IrOp;

typedef int ValueName;

/* 全局初始化指针重定位：blob 内偏移 (小端坐标) + 目标符号名
 * （用于 int *p = &x / struct 内指针字段 = &x 等地址初始化） */
typedef struct InitReloc {
    int offset;      /* blob 内偏移 */
    char *symbol;    /* 目标符号名 */
} InitReloc;

typedef struct Instr {
    IrOp        op;
    ValueName   dest;
    Ctype      *type;
    Ctype      *mem_type;   // 内存访问对象类型（用于volatile/register/data）
    List       *args;       // ValueName* 列表
    List       *labels;     // char* 列表（用于跳转目标、符号名）
    union { 
        int64_t ival; 
        double fval; 
        struct {
            unsigned char *bytes;
            int len;
            List *relocs;   /* InitReloc* 列表（指针字段地址重定位） */
        } blob; // 数组/结构/联合等初始化字节序列
    } imm;
} Instr;

typedef struct Block {
    uint32_t    id;
    bool        sealed;
    List       *preds;      // Block* 列表
    List       *instrs;     // Instr* 列表
    List       *phis;       // Instr* 列表（IROP_PHI）
    Dict       *var_map;    // char* -> ValueName*
    List       *incomplete; // IncompletePhi* 列表
} Block;

typedef struct Func {
    const char  *name;
    Ctype       *ret_type;
    List        *params;    // char* 列表
    List        *param_types; // Ctype* 列表
    List        *blocks;    // Block* 列表
    Block       *entry;
    Dict        *stack_offsets; // 局部变量栈偏移 (char* -> int*)
    int          stack_size;
    bool        is_inline;
    bool        is_noreturn;
    // 中断函数信息
    bool        is_interrupt;
    int         interrupt_id;
    int         bank_id;
} Func;

// 全局变量信息（用于C51代码生成）
typedef struct GlobalVar {
    char        *name;
    Ctype       *type;
    long         init_value;    // 初始值（仅支持整数）
    bool         has_init;      // 是否有初始值
    Instr       *init_instr;    // 可选：初始化指令（数组/结构/联合等，数据在 imm.blob）
    bool         is_static;
    bool         is_extern;
} GlobalVar;

typedef struct SSAUnit {
    List    *funcs;         // Func* 列表
    List    *globals;       // GlobalVar* 列表（C51全局变量）

    /* 顶层 asm 块（来自文件作用域的 __asm__("...");） */
    List    *asm_blocks;    // char* 列表（raw asm text）
} SSAUnit;

typedef struct SSABuild {
    SSAUnit     *unit;
    Func        *cur_func;
    Block       *cur_block;
    struct CFContext *cf_ctx;  // 控制流上下文，定义在ssa.c中
    int          next_value;
    uint32_t     next_block;
    /* 已取地址的局部变量集合：取地址后值可被指针写改变，
     * 后续 read 必须走内存 load 而非 var_map SSA 值 (0005-ifstmt 根因)。 */
    Dict        *taken_addr;   /* char* 变量名 -> int* 1 */

    /* 延迟的 trivial phi 替换 (0042-prime/0041-queen 悬空值根因):
     * phi 的 use 可能在其 seal 之后才发射, 立即 replace_uses 会漏掉
     * 后续指令 → 引用已 NOP 的 phi dest → 死循环。函数构建完成后统一应用。 */
    List        *pending_replace; /* PendingReplace* 列表 */
} SSABuild;

/* ============================================================
 * 仅暴露的4个API
 * ============================================================ */

SSABuild* ssa_build_create(void);
void      ssa_build_destroy(SSABuild *b);
void      ast_to_ssa(SSABuild *b, Ast *ast);

void      ssa_print_instr(FILE *fp, Instr *i, List *consts);
void      ssa_print_func(FILE *fp, Func *f);
void      ssa_print(FILE *fp, SSAUnit *unit);

void      ssa_add_global(SSABuild *b, const char *name, Ctype *type, long init_value, bool has_init,
                         Instr *init_instr,
                         bool is_static, bool is_extern);

/* ============================================================
 * 优化 Pass API (ssa_pass.c)
 * ============================================================ */

typedef enum OptimizationLevel {
    OPT_O0 = 0,     // 无优化
    OPT_O1 = 1,     // 基本优化
    OPT_O2 = 2,     // 激进优化
    OPT_OS = 3      // 大小优化
} OptimizationLevel;

// 对单个函数进行优化
void ssa_optimize_func(Func *f, int level);

// 对整个 SSA Unit 进行优化
void ssa_optimize(SSAUnit *unit, int level);

#endif