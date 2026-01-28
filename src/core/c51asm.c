/* c51asm.c - 8051汇编指令缓冲区实现
 */

#include "c51asm.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

static const char *c51_reg_names[C51_REG_COUNT] = {
    "A", "B",
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
    "DPTR", "SP", "C", "PC"
};

static const char *c51_op_names[C51_COUNT] = {
    "NOP",
    "MOV", "PUSH", "POP", "XCH", "XCHD",
    "ADD", "ADDC", "SUBB", "INC", "DEC", "MUL", "DIV", "DA",
    "ANL", "ORL", "XRL", "CLR", "CPL", "RL", "RLC", "RR", "RRC",
    "SETB",
    "JZ", "JNZ", "JC", "JNC", "JB", "JNB", "JBC",
    "SJMP", "AJMP", "LJMP", "JMP",
    "ACALL", "LCALL", "RET", "RETI",
    "LABEL", "COMMENT", "DIRECTIVE", "RAW"
};

/* ============================================================
 * 内存管理
 * ============================================================ */

typedef struct C51Pool {
    char *base;
    char *ptr;
    size_t size;
    size_t used;
    struct C51Pool *next;
} C51Pool;

#define POOL_BLOCK_SIZE (64 * 1024)  // 64KB 块

static C51Pool* pool_create(void) {
    C51Pool *pool = malloc(sizeof(C51Pool));
    pool->base = malloc(POOL_BLOCK_SIZE);
    pool->ptr = pool->base;
    pool->size = POOL_BLOCK_SIZE;
    pool->used = 0;
    pool->next = NULL;
    return pool;
}

static void pool_free(C51Pool *pool) {
    while (pool) {
        C51Pool *next = pool->next;
        free(pool->base);
        free(pool);
        pool = next;
    }
}

static void pool_reset(C51Pool *pool) {
    pool->ptr = pool->base;
    pool->used = 0;
    if (pool->next) {
        pool_free(pool->next);
        pool->next = NULL;
    }
}

static void* pool_alloc(C51Pool *pool, size_t size) {
    size = (size + 7) & ~7;  // 8字节对齐
    if (pool->used + size > pool->size) {
        // 需要新块
        if (!pool->next) {
            pool->next = pool_create();
        }
        return pool_alloc(pool->next, size);
    }
    void *p = pool->ptr;
    pool->ptr += size;
    pool->used += size;
    return p;
}

static char* pool_strdup(C51Pool *pool, const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = pool_alloc(pool, len);
    memcpy(p, s, len);
    return p;
}

/* ============================================================
 * C51Line 内存管理
 * ============================================================ */

static void free_line(C51Line *line) {
    if (!line) return;
    // 释放标签字符串
    if (line->dst.type == C51_OP_LABEL && line->dst.label) {
        free((void*)line->dst.label);
    }
    if (line->src.type == C51_OP_LABEL && line->src.label) {
        free((void*)line->src.label);
    }
    // 释放注释
    if (line->comment) {
        free((void*)line->comment);
    }
    // 释放 RAW 数据
    if (line->op == C51_RAW && line->src.label) {
        free((void*)line->src.label);
    }
    free(line);
}

/* ============================================================
 * 缓冲区管理
 * ============================================================ */

C51Buffer* c51_buffer_create(void) {
    C51Buffer *buf = calloc(1, sizeof(C51Buffer));
    buf->base_addr = 0;
    return buf;
}

void c51_buffer_reset(C51Buffer *buf) {
    C51Line *line = buf->head;
    while (line) {
        C51Line *next = line->next;
        free_line(line);
        line = next;
    }
    buf->head = NULL;
    buf->tail = NULL;
    buf->count = 0;
    buf->symtab.count = 0;
}

void c51_buffer_free(C51Buffer *buf) {
    if (!buf) return;
    c51_buffer_reset(buf);
    free(buf->symtab.syms);
    free(buf);
}

void c51_buffer_set_base(C51Buffer *buf, uint16_t addr) {
    buf->base_addr = addr;
}

/* ============================================================
 * 指令添加
 * ============================================================ */

static C51Line* new_line(C51Buffer *buf) {
    C51Line *line = calloc(1, sizeof(C51Line));
    line->next = NULL;
    
    if (buf->tail) {
        buf->tail->next = line;
    } else {
        buf->head = line;
    }
    buf->tail = line;
    buf->count++;
    return line;
}

void c51_emit(C51Buffer *buf, C51Op op, C51Operand dst, C51Operand src, const char *comment) {
    C51Line *line = new_line(buf);
    line->op = op;
    line->dst = dst;
    line->src = src;
    line->comment = comment;
}

void c51_emit_mov(C51Buffer *buf, C51Operand dst, C51Operand src) {
    c51_emit(buf, C51_MOV, dst, src, NULL);
}

void c51_emit_alu(C51Buffer *buf, C51Op op, C51Operand dst, C51Operand src) {
    c51_emit(buf, op, dst, src, NULL);
}

void c51_emit_unary(C51Buffer *buf, C51Op op, C51Operand opd) {
    c51_emit(buf, op, opd, c51_none(), NULL);
}

void c51_emit_jump(C51Buffer *buf, C51Op op, const char *label) {
    assert(op == C51_SJMP || op == C51_AJMP || op == C51_LJMP);
    C51Line *line = new_line(buf);
    line->op = op;
    line->dst.type = C51_OP_LABEL;
    line->dst.label = strdup(label);
    line->src = c51_none();
}

void c51_emit_branch(C51Buffer *buf, C51Op op, C51Operand cond, const char *label) {
    C51Line *line = new_line(buf);
    line->op = op;
    line->dst = cond;
    line->src.type = C51_OP_LABEL;
    line->src.label = strdup(label);
}

void c51_emit_call(C51Buffer *buf, const char *func, bool is_long) {
    C51Line *line = new_line(buf);
    line->op = is_long ? C51_LCALL : C51_ACALL;
    line->dst.type = C51_OP_LABEL;
    line->dst.label = strdup(func);
    line->src = c51_none();
}

void c51_emit_ret(C51Buffer *buf) {
    c51_emit(buf, C51_RET, c51_none(), c51_none(), NULL);
}

void c51_emit_push(C51Buffer *buf, C51Operand opd) {
    c51_emit(buf, C51_PUSH, opd, c51_none(), NULL);
}

void c51_emit_pop(C51Buffer *buf, C51Operand opd) {
    c51_emit(buf, C51_POP, opd, c51_none(), NULL);
}

void c51_emit_label(C51Buffer *buf, const char *name) {
    C51Line *line = new_line(buf);
    line->op = C51_LABEL;
    line->dst.type = C51_OP_LABEL;
    line->dst.label = strdup(name);
}

void c51_emit_comment(C51Buffer *buf, const char *fmt, ...) {
    // 评论作为特殊指令存储，fmt在打印时展开
    C51Line *line = new_line(buf);
    line->op = C51_COMMENT;
    // 这里简化处理，直接格式化
    static char text[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    line->comment = strdup(text);  // 需要复制，因为是临时的
}

void c51_emit_directive(C51Buffer *buf, const char *text) {
    C51Line *line = new_line(buf);
    line->op = C51_DIRECTIVE;
    line->comment = strdup(text);
}

void c51_emit_org(C51Buffer *buf, uint16_t addr) {
    c51_buffer_set_base(buf, addr);
    c51_emit_directive(buf, "ORG");
}

void c51_emit_db(C51Buffer *buf, const uint8_t *data, int len) {
    // 作为原始数据处理
    C51Line *line = new_line(buf);
    line->op = C51_RAW;
    line->dst.type = C51_OP_IMM;
    line->dst.imm = len;
    uint8_t *copy = malloc(len);
    memcpy(copy, data, len);
    // 通过src的label字段存储 (有点hack)
    line->src.type = C51_OP_NONE;
    line->src.label = (char*)copy;
}

/* ============================================================
 * 辅助函数
 * ============================================================ */

const char* c51_reg_name(C51Reg reg) {
    if (reg >= 0 && reg < C51_REG_COUNT) return c51_reg_names[reg];
    return "?";
}

const char* c51_op_name(C51Op op) {
    if (op >= 0 && op < C51_COUNT) return c51_op_names[op];
    return "?";
}

// 计算指令大小
int c51_insn_size(C51Line *line) {
    if (!line) return 0;
    
    switch (line->op) {
    case C51_NOP: return 1;
    case C51_INC:
    case C51_DEC:
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A) return 1;
        if (line->dst.type == C51_OP_REG) return 1;  // INC Rn
        if (line->dst.type == C51_OP_DIRECT) return 2;  // INC direct
        if (line->dst.type == C51_OP_INDIRECT) return 1;  // INC @Ri
        return 1;
    case C51_ADD:
    case C51_ADDC:
    case C51_SUBB:
        if (line->src.type == C51_OP_IMM) return 2;
        if (line->src.type == C51_OP_DIRECT) return 2;
        if (line->src.type == C51_OP_REG) return 1;
        if (line->src.type == C51_OP_INDIRECT) return 1;
        return 1;
    case C51_MOV:
        // MOV 有多种变体，这里简化处理
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A) {
            if (line->src.type == C51_OP_IMM) return 2;
            if (line->src.type == C51_OP_DIRECT) return 2;
            if (line->src.type == C51_OP_INDIRECT) return 1;
            if (line->src.type == C51_OP_REG) return 1;
        }
        if (line->dst.type == C51_OP_DIRECT) return 2;  // MOV direct, A 或 MOV direct, #imm
        return 2;
    case C51_PUSH:
    case C51_POP:
        return 2;
    case C51_MUL:
    case C51_DIV:
        return 1;
    case C51_CLR:
    case C51_CPL:
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A) return 1;
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_C) return 1;
        return 1;
    case C51_ANL:
    case C51_ORL:
    case C51_XRL:
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A) {
            if (line->src.type == C51_OP_IMM) return 2;
            if (line->src.type == C51_OP_DIRECT) return 2;
            if (line->src.type == C51_OP_REG) return 1;
            if (line->src.type == C51_OP_INDIRECT) return 1;
        }
        return 2;
    case C51_RL:
    case C51_RLC:
    case C51_RR:
    case C51_RRC:
        return 1;
    case C51_SJMP: return 2;
    case C51_AJMP: return 2;
    case C51_LJMP: return 3;
    case C51_ACALL: return 2;
    case C51_LCALL: return 3;
    case C51_RET:
    case C51_RETI:
        return 1;
    case C51_JZ:
    case C51_JNZ:
    case C51_JC:
    case C51_JNC:
        return 2;
    case C51_JB:
    case C51_JNB:
    case C51_JBC:
        return 3;
    case C51_LABEL:
    case C51_COMMENT:
        return 0;  // 不生成代码
    case C51_DIRECTIVE:
        return 0;  // 伪指令不产生代码
    case C51_RAW:
        return line->dst.imm;
    default:
        return 1;
    }
}

bool c51_find_symbol(C51Buffer *buf, const char *name, uint16_t *out_addr) {
    for (int i = 0; i < buf->symtab.count; i++) {
        if (strcmp(buf->symtab.syms[i].name, name) == 0) {
            if (out_addr) *out_addr = buf->symtab.syms[i].addr;
            return true;
        }
    }
    return false;
}

/* ============================================================
 * 地址计算
 * ============================================================ */

void c51_calc_addresses(C51Buffer *buf) {
    uint16_t addr = buf->base_addr;
    
    // 清理符号表
    buf->symtab.count = 0;
    
    for (C51Line *line = buf->head; line; line = line->next) {
        line->addr = addr;
        line->size = c51_insn_size(line);
        addr += line->size;
        
        // 记录标签
        if (line->op == C51_LABEL && line->dst.label) {
            if (buf->symtab.count >= buf->symtab.capacity) {
                buf->symtab.capacity = buf->symtab.capacity ? buf->symtab.capacity * 2 : 16;
                buf->symtab.syms = realloc(buf->symtab.syms, 
                    buf->symtab.capacity * sizeof(C51Symbol));
            }
            C51Symbol *sym = &buf->symtab.syms[buf->symtab.count++];
            sym->name = line->dst.label;
            sym->addr = line->addr;
            sym->line = line;
            sym->is_global = false;
        }
    }
}

/* ============================================================
 * 优化
 * ============================================================ */

void c51_optimize_jumps(C51Buffer *buf) {
    c51_calc_addresses(buf);
    
    for (C51Line *line = buf->head; line; line = line->next) {
        if (line->op == C51_LJMP && line->dst.type == C51_OP_LABEL) {
            uint16_t target;
            if (c51_find_symbol(buf, line->dst.label, &target)) {
                int offset = (int)target - (int)(line->addr + 2);
                if (offset >= -128 && offset <= 127) {
                    line->op = C51_SJMP;
                    line->src = c51_rel(offset);
                } else if ((line->addr & 0xF800) == (target & 0xF800)) {
                    // 在同一2KB页，可以使用AJMP
                    line->op = C51_AJMP;
                }
            }
        }
    }
    // 重新计算地址
    c51_calc_addresses(buf);
}

void c51_optimize_peephole(C51Buffer *buf) {
    if (!buf || !buf->head) return;
    
    bool changed = true;
    while (changed) {
        changed = false;
        
        for (C51Line *line = buf->head; line && line->next; line = line->next) {
            C51Line *next = line->next;
            
            // 模式1: MOV A, Rx; MOV Rx, A -> 删除第二条
            if (line->op == C51_MOV && next->op == C51_MOV) {
                if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A &&
                    line->src.type == C51_OP_REG &&
                    next->dst.type == C51_OP_REG &&
                    next->dst.reg == line->src.reg &&
                    next->src.type == C51_OP_REG && next->src.reg == C51_REG_A) {
                    // 删除第二条指令
                    line->next = next->next;
                    if (buf->tail == next) buf->tail = line;
                    free_line(next);
                    changed = true;
                    continue;
                }
            }
            
            // 模式2: MOV Rx, A; MOV A, Rx -> 删除第二条
            if (line->op == C51_MOV && next->op == C51_MOV) {
                if (line->dst.type == C51_OP_REG &&
                    line->src.type == C51_OP_REG && line->src.reg == C51_REG_A &&
                    next->dst.type == C51_OP_REG && next->dst.reg == C51_REG_A &&
                    next->src.type == C51_OP_REG &&
                    next->src.reg == line->dst.reg) {
                    // 删除第二条指令
                    line->next = next->next;
                    if (buf->tail == next) buf->tail = line;
                    free_line(next);
                    changed = true;
                    continue;
                }
            }
            
            // 模式3: MOV A, A -> 删除
            if (line->op == C51_MOV &&
                line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A &&
                line->src.type == C51_OP_REG && line->src.reg == C51_REG_A) {
                // 删除这条指令
                C51Line *prev = buf->head;
                if (prev == line) {
                    buf->head = line->next;
                } else {
                    while (prev && prev->next != line) prev = prev->next;
                    if (prev) prev->next = line->next;
                }
                if (buf->tail == line) buf->tail = prev;
                C51Line *to_free = line;
                line = line->next;
                free_line(to_free);
                changed = true;
                continue;
            }
            
            // 模式4: CLR A; MOV A, #0 -> 保留CLR A（更短）
            // 模式5: MOV A, #0 -> CLR A（优化为更短的指令）
            if (line->op == C51_MOV &&
                line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A &&
                line->src.type == C51_OP_IMM && line->src.imm == 0) {
                line->op = C51_CLR;
                line->src = c51_none();
                changed = true;
                continue;
            }
            
            // 模式6: SJMP .+2 (跳转到下一条) -> 删除
            if (line->op == C51_SJMP && line->src.type == C51_OP_REL) {
                if (line->src.imm == 0) {
                    // 删除这条指令
                    C51Line *prev = buf->head;
                    if (prev == line) {
                        buf->head = line->next;
                    } else {
                        while (prev && prev->next != line) prev = prev->next;
                        if (prev) prev->next = line->next;
                    }
                    if (buf->tail == line) buf->tail = prev;
                    C51Line *to_free = line;
                    line = line->next;
                    free_line(to_free);
                    changed = true;
                    continue;
                }
            }
            
            // 模式7: LJMP label; LJMP label (连续相同跳转) -> 删除第二条
            if (line->op == C51_LJMP && next->op == C51_LJMP) {
                if (line->dst.type == C51_OP_LABEL && next->dst.type == C51_OP_LABEL &&
                    line->dst.label && next->dst.label &&
                    strcmp(line->dst.label, next->dst.label) == 0) {
                    line->next = next->next;
                    if (buf->tail == next) buf->tail = line;
                    free_line(next);
                    changed = true;
                    continue;
                }
            }
            
            // 模式8: MOV direct, A; MOV A, direct -> 如果direct相同，删除第二条
            if (line->op == C51_MOV && next->op == C51_MOV) {
                if (line->dst.type == C51_OP_DIRECT &&
                    line->src.type == C51_OP_REG && line->src.reg == C51_REG_A &&
                    next->dst.type == C51_OP_REG && next->dst.reg == C51_REG_A &&
                    next->src.type == C51_OP_DIRECT &&
                    line->dst.imm == next->src.imm) {
                    line->next = next->next;
                    if (buf->tail == next) buf->tail = line;
                    free_line(next);
                    changed = true;
                    continue;
                }
            }
        }
    }
}

/* ============================================================
 * 输出: 汇编格式
 * ============================================================ */

static void print_operand(FILE *fp, C51Operand op) {
    switch (op.type) {
    case C51_OP_NONE:
        break;
    case C51_OP_REG:
        fprintf(fp, "%s", c51_reg_name(op.reg));
        break;
    case C51_OP_IMM:
        fprintf(fp, "#0x%02X", (uint8_t)op.imm);
        break;
    case C51_OP_DIRECT:
        fprintf(fp, "0x%02X", (uint8_t)op.imm);
        break;
    case C51_OP_INDIRECT:
        fprintf(fp, "@%s", c51_reg_name(op.reg));
        break;
    case C51_OP_LABEL:
        fprintf(fp, "%s", op.label);
        break;
    case C51_OP_REL:
        fprintf(fp, "%+d", op.imm);
        break;
    }
}

void c51_print_asm(C51Buffer *buf, FILE *fp) {
    for (C51Line *line = buf->head; line; line = line->next) {
        // 标签单独一行
        if (line->op == C51_LABEL) {
            fprintf(fp, "%s:\n", line->dst.label);
            continue;
        }
        
        // 注释
        if (line->op == C51_COMMENT) {
            fprintf(fp, "; %s\n", line->comment);
            continue;
        }
        
        // 伪指令
        if (line->op == C51_DIRECTIVE) {
            fprintf(fp, "    %s\n", line->comment);
            continue;
        }
        
        // 原始数据
        if (line->op == C51_RAW) {
            uint8_t *data = (uint8_t*)line->src.label;
            fprintf(fp, "    DB ");
            for (int i = 0; i < line->dst.imm; i++) {
                if (i > 0) fprintf(fp, ", ");
                fprintf(fp, "0x%02X", data[i]);
            }
            fprintf(fp, "\n");
            continue;
        }
        
        // 普通指令
        fprintf(fp, "    %s", c51_op_name(line->op));
        
        // 操作数
        if (line->dst.type != C51_OP_NONE) {
            fprintf(fp, " ");
            print_operand(fp, line->dst);
            if (line->src.type != C51_OP_NONE) {
                fprintf(fp, ", ");
                print_operand(fp, line->src);
            }
        }
        
        // 行内注释
        if (line->comment) {
            fprintf(fp, " ; %s", line->comment);
        }
        
        fprintf(fp, "\n");
    }
}

/* ============================================================
 * 输出: Intel HEX 格式
 * ============================================================ */

static uint8_t calc_checksum(uint8_t *data, int len, uint16_t addr, uint8_t type) {
    uint8_t sum = len + (addr >> 8) + (addr & 0xFF) + type;
    for (int i = 0; i < len; i++) sum += data[i];
    return (~sum + 1) & 0xFF;
}

static void print_hex_line(FILE *fp, uint16_t addr, uint8_t *data, int len) {
    fprintf(fp, ":%02X%04X00", len, addr);
    for (int i = 0; i < len; i++) {
        fprintf(fp, "%02X", data[i]);
    }
    fprintf(fp, "%02X\n", calc_checksum(data, len, addr, 0));
}

int c51_encode_insn(C51Line *line, uint8_t *out, int max_len) {
    if (!line || max_len < 3) return 0;
    
    // 简化实现：只编码部分常用指令
    switch (line->op) {
    case C51_NOP:
        out[0] = 0x00;
        return 1;
    case C51_RET:
        out[0] = 0x22;
        return 1;
    case C51_RETI:
        out[0] = 0x32;
        return 1;
    case C51_MOV:
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A) {
            if (line->src.type == C51_OP_IMM) {
                out[0] = 0x74;
                out[1] = (uint8_t)line->src.imm;
                return 2;
            }
            if (line->src.type == C51_OP_DIRECT) {
                out[0] = 0xE5;
                out[1] = (uint8_t)line->src.imm;
                return 2;
            }
            if (line->src.type == C51_OP_INDIRECT) {
                if (line->src.reg == C51_REG_R0) out[0] = 0xE6;
                if (line->src.reg == C51_REG_R1) out[0] = 0xE7;
                return 1;
            }
            if (line->src.type == C51_OP_REG) {
                out[0] = 0xE8 + (line->src.reg - C51_REG_R0);
                return 1;
            }
        }
        break;
    case C51_ADD:
        if (line->dst.type == C51_OP_REG && line->dst.reg == C51_REG_A) {
            if (line->src.type == C51_OP_IMM) {
                out[0] = 0x24;
                out[1] = (uint8_t)line->src.imm;
                return 2;
            }
        }
        break;
    case C51_SJMP:
        out[0] = 0x80;
        if (line->src.type == C51_OP_REL) {
            out[1] = (uint8_t)line->src.imm;
        } else {
            out[1] = 0x00;  // 默认
        }
        return 2;
    case C51_LJMP:
        out[0] = 0x02;
        {
            uint16_t target = 0;
            // 这里需要查找标签地址
            out[1] = target >> 8;
            out[2] = target & 0xFF;
        }
        return 3;
    default:
        break;
    }
    return 0;  // 未实现
}

void c51_print_hex(C51Buffer *buf, FILE *fp) {
    uint8_t data[16];
    int data_len = 0;
    uint16_t line_addr = 0;
    
    for (C51Line *line = buf->head; line; line = line->next) {
        if (line->size == 0) continue;
        
        if (data_len == 0) {
            line_addr = line->addr;
        }
        
        // 编码指令
        uint8_t encoded[4];
        int n = c51_encode_insn(line, encoded, sizeof(encoded));
        
        // 添加到数据缓冲区
        for (int i = 0; i < n && data_len < 16; i++) {
            data[data_len++] = encoded[i];
        }
        
        // 输出满行或非连续地址
        if (data_len >= 16 || 
            (line->next && line->next->addr != line->addr + line->size)) {
            print_hex_line(fp, line_addr, data, data_len);
            data_len = 0;
        }
    }
    
    // 输出剩余数据
    if (data_len > 0) {
        print_hex_line(fp, line_addr, data, data_len);
    }
    
    // 文件结束标记
    fprintf(fp, ":00000001FF\n");
}

/* ============================================================
 * Link文件生成 (符号表和重定位信息)
 * ============================================================ */

void c51_print_link(C51Buffer *buf, FILE *fp) {
    fprintf(fp, "; C51 Linker File\n");
    fprintf(fp, "; Generated from SSA IR\n\n");
    
    // 输出符号表
    fprintf(fp, "; Symbol Table\n");
    fprintf(fp, "; Name\t\tAddress\tType\n");
    fprintf(fp, "; ------------------------------\n");
    
    for (int i = 0; i < buf->symtab.count; i++) {
        C51Symbol *sym = &buf->symtab.syms[i];
        fprintf(fp, "SYMBOL\t%s\t0x%04X\t%s\n",
                sym->name,
                sym->addr,
                sym->is_global ? "GLOBAL" : "LOCAL");
    }
    
    fprintf(fp, "\n; Memory Map\n");
    fprintf(fp, "; Segment\tStart\tEnd\tSize\n");
    fprintf(fp, "; ------------------------------\n");
    
    uint16_t end_addr = buf->base_addr;
    if (buf->tail) {
        end_addr = buf->tail->addr + buf->tail->size;
    }
    fprintf(fp, "SEGMENT\tCODE\t0x%04X\t0x%04X\t%d\n",
            buf->base_addr,
            end_addr,
            end_addr - buf->base_addr);
    
    fprintf(fp, "\n; External References\n");
    fprintf(fp, "; Name\t\tLocation\n");
    fprintf(fp, "; ------------------------------\n");
    
    // 遍历指令查找外部引用（标签引用）
    for (C51Line *line = buf->head; line; line = line->next) {
        if (line->dst.type == C51_OP_LABEL && line->op != C51_LABEL) {
            fprintf(fp, "EXTERN\t%s\t0x%04X\n", line->dst.label, line->addr);
        }
        if (line->src.type == C51_OP_LABEL) {
            fprintf(fp, "EXTERN\t%s\t0x%04X\n", line->src.label, line->addr);
        }
    }
    
    fprintf(fp, "\n; End of Link File\n");
}

/* ============================================================
 * 多格式输出 API
 * ============================================================ */

void c51_gen_all_formats(C51Buffer *buf, const char *basename) {
    char filename[256];
    FILE *fp;
    
    // 输出 .asm 文件
    snprintf(filename, sizeof(filename), "%s.asm", basename);
    fp = fopen(filename, "w");
    if (fp) {
        printf("Writing ASM file: %s\n", filename);
        c51_print_asm(buf, fp);
        fclose(fp);
    }
    
    // 输出 .hex 文件 (Intel HEX格式)
    snprintf(filename, sizeof(filename), "%s.hex", basename);
    fp = fopen(filename, "w");
    if (fp) {
        printf("Writing HEX file: %s\n", filename);
        c51_print_hex(buf, fp);
        fclose(fp);
    }
    
    // 输出 .lnk 文件 (链接信息)
    snprintf(filename, sizeof(filename), "%s.lnk", basename);
    fp = fopen(filename, "w");
    if (fp) {
        printf("Writing LINK file: %s\n", filename);
        c51_print_link(buf, fp);
        fclose(fp);
    }
}
