#ifndef __SSA_H__
#define __SSA_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "list.h"
#include "dict.h"
#include "cc.h"

typedef enum IrOp {
    IROP_NOP = 0, IROP_CONST, IROP_ADD, IROP_MUL, IROP_SUB, IROP_DIV,
    IROP_EQ, IROP_LT, IROP_GT, IROP_LE, IROP_GE,
    IROP_NOT, IROP_AND, IROP_OR,
    IROP_JMP, IROP_BR, IROP_CALL, IROP_RET, IROP_PRINT,
    IROP_PHI, IROP_ALLOC, IROP_FREE, IROP_STORE, IROP_LOAD, IROP_PTRADD,
    IROP_FADD, IROP_FMUL, IROP_FSUB, IROP_FDIV,
    IROP_FEQ, IROP_FLT, IROP_FLE, IROP_FGT, IROP_FGE,
    IROP_LCONST
} IrOp;

typedef struct Instr {
    int         op;    
    const char *dest;       /* SSA 名，NULL 表示无 dest     */
    Ctype       *type;      /* dest 存在时必须, 这里直接复用 */
    List *args;             /* SSA 源数组 const char *      */
    List *labels;           /* 标签数组 const char *        */
    union {
        int64_t ival;
        double fval;
        List *array_val;
        List *struct_val;
    };
    struct { int restrict_:1, volatile_:1, reg:1, mem:3; } attr;
} Instr;

typedef struct Block {
    uint32_t id;
    bool     sealed;

    List    *instrs;            // List<*Instr>
    List    *pred_ids;          // List<uint32_t>
    List    *succ_ids;          // List<uint32_t>
} Block;

typedef struct Func {
    const char  *name;
    Ctype       *ret_type;

    List        *param_names;   // List<const char *>
    List        *blocks;        // List<Block>
    uint32_t    entry_id;
} Func;

typedef struct Global {
    const char *name;
    Ctype      *type;
    bool        is_extern;
    union { int64_t i; double f; } init;
} Global;

typedef struct SSAUnit {
    List    *globals;           // List<Global>
    List     *funcs;            // List<Func>
} SSAUnit;

typedef struct SSABuild {
    SSAUnit *unit;
    Func    *cur_func;
    Block   *cur_block;
    
    List    *instr_buf;         // List<*Instr> 指令池 
    List    *name_buf;          // List<const char *> 名字池 
    Dict    *var_map;
} SSABuild;

#endif /* __SSA_H__ */