#ifndef SSA_H
#define SSA_H

// 参考网址: https://zhuanlan.zhihu.com/p/360692294
// https://fiking.github.io/2022/04/30/%E7%AE%80%E5%8D%95%E4%B8%94%E9%AB%98%E6%95%88%E7%9A%84%E9%9D%99%E6%80%81%E5%8D%95%E4%B8%80%E8%B5%8B%E5%80%BC%E5%BD%A2%E5%BC%8F%E6%9E%84%E9%80%A0/

#include <stdint.h>
#include "list.h"
#include "dict.h"

enum IrOp {
    IROP_NOP    = 0,
    IROP_CONST  = 1,
    IROP_ADD    = 2,
    IROP_MUL    = 3,
    IROP_SUB    = 4,
    IROP_DIV    = 5,
    IROP_EQ     = 6,
    IROP_LT     = 7,
    IROP_GT     = 8,
    IROP_LE     = 9,
    IROP_GE     = 10,
    IROP_NOT    = 11,
    IROP_AND    = 12,
    IROP_OR     = 13,
    IROP_JMP    = 14,
    IROP_BR     = 15,
    IROP_CALL   = 16,
    IROP_RET    = 17,
    IROP_PRINT  = 18,
    IROP_PHI    = 19,
    IROP_ALLOC  = 20,
    IROP_FREE   = 21,
    IROP_STORE  = 22,
    IROP_LOAD   = 23,
    IROP_PTRADD = 24,
    /* --- 浮点 --- */
    IROP_FADD   = 25,
    IROP_FMUL   = 26,
    IROP_FSUB   = 27,
    IROP_FDIV   = 28,
    IROP_FEQ    = 29,
    IROP_FLT    = 30,
    IROP_FLE    = 31,
    IROP_FGT    = 32,
    IROP_FGE    = 33,
    /* --- 长常数 --- */
    IROP_LCONST = 34
};

/* --------------- 类型 --------------- */
typedef struct Type {
    const char *ctor;   /* "int" "uint" "float" */
    uint8_t     bits;   /* 8 16 32 64           */
    int         unsign; /* 0 或 1               */
    int         ptr;    /* 0 或 1               */
} Type;

/* --------------- 指令 --------------- */
typedef struct Instr {
    const char *op;     /* "add" "const" "phi" ... */
    const char *dest;   /* SSA 名，NULL 表示无 dest */
    Type       *type;   /* dest 存在时必须        */
    const char **args;  /* NULL 结尾的 SSA 源数组  */
    const char **labels;/* NULL 结尾的标签数组    */
    union {             /* const 专用              */
        int64_t ival;
        double fval;
    };
    struct { int restrict_:1, volatile_:1, reg:1, mem:3; } attr;
} Instr;

/* --------------- 基本块 --------------- */
typedef struct BlockExtra BlockExtra;   /* 前向声明 */

typedef struct Block {
    int   id;
    Instr **insts;      /* NULL 结尾的普通指令     */
    Instr **phinodes;   /* NULL 结尾的 phi 指令    */
    /* SSA+ CFG */
    BlockExtra *extra;  /* 指向 BlockExtra，NULL 表示尚未构建 CFG */
} Block;

/* --------------- 函数 --------------- */
typedef struct SSABuild SSABuild;       /* 前向声明 */

typedef struct Func {
    const char *name;
    Type       *type;   /* 返回类型                */
    const char **params;/* NULL 结尾的形参 SSA 名  */
    struct { int inline_:1, noreturn:1; } attr;
    Block     **blocks; /* NULL 结尾               */
    Block      *entry;  /* 入口块                  */
    /* SSA+ 构建上下文指针，转换阶段有效，发射后可置 NULL */
    SSABuild   *build;
} Func;

/* --------------- 全局变量 --------------- */
typedef struct Global {
    const char *name;
    Type       *type;
    int         extern_;
    const char *static_; /* "file" 或 "func" 或 NULL */
    int64_t     init;
} Global;

/* --------------- 一整份 IR --------------- */
typedef struct SSAUnit {
    Global **globals;
    Func   **funcs;
} SSAUnit;

/*==================== 阶段 0：全局构建上下文 ====================*/
struct SSABuild {
    Func     *f;                /* 当前函数 */
    Dict     *astVar2ssa;       /* AST 局部变量 → 当前 SSA 名字 */
    Dict     *block2extra;      /* Block → BlockExtra* */
    int       anonSeq;          /* 匿名临时序号生成器 */

    /*-------- 阶段 1：CFG 遍历 --------*/
    List     *workList;         /* Block* 队列 */

    /*-------- 阶段 2：支配信息 --------*/
    List     *idom;             /* Block* []      立即支配者 */
    List     *domTree;          /* List<Block*>[] 支配树孩子 */
    List     *domFrontier;      /* List<Block*>[] 支配边界 DF */

    /*-------- 阶段 3：φ 与 重命名 --------*/
    Dict     *sealedBlocks;     /* Block* → bool           是否密封 */
    Dict     *phiOps;           /* Block* → List<PhiOp*>   待补 φ 操作数 */
};

/*==================== 阶段 1：基本块扩展 ====================*/
struct BlockExtra {
    Block   *block;
    List    *preds;             /* Block* 前驱 */
    List    *succs;             /* Block* 后继 */
};

/*==================== 阶段 3：φ 操作数回填记录 ====================*/
typedef struct PhiOp {
    Instr *phi;                 /* 所属 phi 指令 */
    Block *pred;                /* 缺少该前驱的值 */
} PhiOp;

/*==================== 阶段 3：重命名栈（每变量一个栈） ====================*/
typedef struct RenameStack {
    Dict *stacks;               /* char* var → List<char*>*  SSA 名字栈 */
} RenameStack;

#endif /* SSA_H */