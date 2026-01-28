/* c51asm.h - 8051汇编指令缓冲区
 * 用于存储汇编指令，支持多格式输出和后期优化
 */

#ifndef C51ASM_H
#define C51ASM_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 * 基础类型定义
 * ============================================================ */

// C51 (8051) 寄存器编号
typedef enum {
    C51_REG_A = 0,
    C51_REG_B,
    C51_REG_R0, C51_REG_R1, C51_REG_R2, C51_REG_R3,
    C51_REG_R4, C51_REG_R5, C51_REG_R6, C51_REG_R7,
    C51_REG_DPTR,
    C51_REG_SP,
    C51_REG_C,      // 进位标志
    C51_REG_PC,     // 程序计数器 (伪寄存器)
    C51_REG_COUNT
} C51Reg;

// 操作数类型
typedef enum {
    C51_OP_NONE = 0,
    C51_OP_REG,         // 寄存器
    C51_OP_IMM,         // 立即数 #value
    C51_OP_DIRECT,      // 直接地址
    C51_OP_INDIRECT,    // 间接寻址 @R0/@R1/@DPTR
    C51_OP_LABEL,       // 标签引用
    C51_OP_REL,         // 相对地址 (用于SJMP等)
} C51OperandType;

// 操作数
typedef struct {
    C51OperandType type;
    union {
        C51Reg reg;         // C51_OP_REG
        int32_t imm;        // C51_OP_IMM / C51_OP_DIRECT / C51_OP_REL
        const char *label;  // C51_OP_LABEL (不拥有内存)
    };
} C51Operand;

// C51汇编指令操作码
typedef enum {
    C51_NOP = 0,
    // 数据传送
    C51_MOV, C51_PUSH, C51_POP, C51_XCH, C51_XCHD,
    // 算术运算
    C51_ADD, C51_ADDC, C51_SUBB, C51_INC, C51_DEC, C51_MUL, C51_DIV, C51_DA,
    // 逻辑运算
    C51_ANL, C51_ORL, C51_XRL, C51_CLR, C51_CPL, C51_RL, C51_RLC, C51_RR, C51_RRC,
    // 位操作
    C51_SETB,
    // 控制转移
    C51_JZ, C51_JNZ, C51_JC, C51_JNC, C51_JB, C51_JNB, C51_JBC,
    C51_SJMP, C51_AJMP, C51_LJMP, C51_JMP,  // JMP = @A+DPTR
    C51_ACALL, C51_LCALL, C51_RET, C51_RETI,
    // 伪指令/元指令
    C51_LABEL,      // 标签定义
    C51_COMMENT,    // 注释行
    C51_DIRECTIVE,  // 汇编伪指令 (.ORG, .DB等)
    C51_RAW,        // 原始字节数据
    C51_COUNT
} C51Op;

/* ============================================================
 * 指令结构
 * ============================================================ */

// 单条C51汇编指令
typedef struct C51Line {
    C51Op op;
    C51Operand dst;     // 目的操作数
    C51Operand src;     // 源操作数
    
    const char *comment; // 可选注释 (不拥有内存)
    
    // 地址信息 (由 calc_addresses 填充)
    uint16_t addr;      // 指令地址
    uint8_t size;       // 指令字节数
    
    struct C51Line *next;
} C51Line;

/* ============================================================
 * 符号表
 * ============================================================ */

typedef struct C51Symbol {
    const char *name;   // 符号名 (不拥有内存)
    uint16_t addr;      // 地址
    C51Line *line;      // 对应的标签行
    bool is_global;     // 是否全局符号
} C51Symbol;

typedef struct C51SymTab {
    C51Symbol *syms;
    int count;
    int capacity;
} C51SymTab;

/* ============================================================
 * 汇编缓冲区
 * ============================================================ */

typedef struct C51Buffer {
    C51Line *head;
    C51Line *tail;
    int count;
    
    C51SymTab symtab;   // 符号表
    uint16_t base_addr; // 基地址 (默认 0)
} C51Buffer;

/* ============================================================
 * API: 缓冲区管理
 * ============================================================ */

C51Buffer* c51_buffer_create(void);
void c51_buffer_free(C51Buffer *buf);
void c51_buffer_reset(C51Buffer *buf);
void c51_buffer_set_base(C51Buffer *buf, uint16_t addr);

/* ============================================================
 * API: 操作数构造 (内联函数)
 * ============================================================ */

static inline C51Operand c51_reg(C51Reg r) {
    return (C51Operand){.type = C51_OP_REG, .reg = r};
}

static inline C51Operand c51_imm(int32_t v) {
    return (C51Operand){.type = C51_OP_IMM, .imm = v};
}

static inline C51Operand c51_direct(int32_t addr) {
    return (C51Operand){.type = C51_OP_DIRECT, .imm = addr};
}

static inline C51Operand c51_indirect(C51Reg r) {
    return (C51Operand){.type = C51_OP_INDIRECT, .reg = r};
}

static inline C51Operand c51_label_ref(const char *label) {
    return (C51Operand){.type = C51_OP_LABEL, .label = label};
}

static inline C51Operand c51_rel(int32_t offset) {
    return (C51Operand){.type = C51_OP_REL, .imm = offset};
}

static inline C51Operand c51_none(void) {
    return (C51Operand){.type = C51_OP_NONE};
}

/* ============================================================
 * API: 指令添加
 * ============================================================ */

// 通用指令添加
void c51_emit(C51Buffer *buf, C51Op op, C51Operand dst, C51Operand src, const char *comment);

// 便捷函数
void c51_emit_mov(C51Buffer *buf, C51Operand dst, C51Operand src);
void c51_emit_alu(C51Buffer *buf, C51Op op, C51Operand dst, C51Operand src);
void c51_emit_unary(C51Buffer *buf, C51Op op, C51Operand opd);
void c51_emit_jump(C51Buffer *buf, C51Op op, const char *label);
void c51_emit_branch(C51Buffer *buf, C51Op op, C51Operand cond, const char *label);
void c51_emit_call(C51Buffer *buf, const char *func, bool is_long);
void c51_emit_ret(C51Buffer *buf);
void c51_emit_push(C51Buffer *buf, C51Operand opd);
void c51_emit_pop(C51Buffer *buf, C51Operand opd);

// 标签和注释
void c51_emit_label(C51Buffer *buf, const char *name);
void c51_emit_comment(C51Buffer *buf, const char *fmt, ...);
void c51_emit_directive(C51Buffer *buf, const char *text);
void c51_emit_org(C51Buffer *buf, uint16_t addr);
void c51_emit_db(C51Buffer *buf, const uint8_t *data, int len);

/* ============================================================
 * API: 处理和输出
 * ============================================================ */

// 计算地址和符号表
void c51_calc_addresses(C51Buffer *buf);

// 优化
void c51_optimize_jumps(C51Buffer *buf);
void c51_optimize_peephole(C51Buffer *buf);

// 输出格式
void c51_print_asm(C51Buffer *buf, FILE *fp);
void c51_print_hex(C51Buffer *buf, FILE *fp);

// 获取指令编码
int c51_encode_insn(C51Line *line, uint8_t *out, int max_len);

/* ============================================================
 * 辅助函数
 * ============================================================ */

const char* c51_reg_name(C51Reg reg);
const char* c51_op_name(C51Op op);
int c51_insn_size(C51Line *line);
bool c51_find_symbol(C51Buffer *buf, const char *name, uint16_t *out_addr);

#endif // C51ASM_H
