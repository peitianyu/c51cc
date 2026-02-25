#include "c51_isel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 寄存器分配相关接口在 c51_regalloc.c 中实现 */
#include "c51_regalloc.h"

/* 辅助函数：将整数键转换为字符串 */
char* int_to_key(int n) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02XH", n);
    return strdup(buf);
}

/* SSA指令转字符串（用于注释） */
char* instr_to_ssa_str(Instr *ins) {
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

/* 获取寄存器名称 */
const char* isel_reg_name(int reg) {
    static const char* names[] = {"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"};
    if (reg >= 0 && reg < 8) return names[reg];
    return "R7";
}

/* 前向声明 */
static void emit_mov(ISelContext* isel, const char* dst, const char* src, Instr* ins);

typedef struct {
    int dst;
    int src; /* -2 表示 A */
} RegMove;

static int reg_index_from_name(const char* s) {
    if (!s) return -1;
    if (s[0] == 'R' && s[1] >= '0' && s[1] <= '7' && s[2] == '\0') {
        return s[1] - '0';
    }
    return -1;
}

/* 分配一个临时寄存器（不修改全局 value_to_reg 映射） */
static int alloc_temp_reg(ISelContext* isel, ValueName val, int size) {
    if (!isel) return -2;
    for (int r = 0; r < 8; r++) {
        if (r + size - 1 > 7) continue;
        bool ok = true;
        for (int j = 0; j < size; j++) {
            if (isel->reg_busy[r + j]) { ok = false; break; }
        }
        if (!ok) continue;
        for (int j = 0; j < size; j++) {
            isel->reg_busy[r + j] = true;
            isel->reg_val[r + j] = val;
        }
        return r;
    }
    return -2; /* 使用 A */
}

/* 判断操作数是否为内存或符号（保守）：非寄存器且非立即即视为内存 */
static bool is_memory_operand_local(const char* op) {
    if (!op) return false;
    if (strcmp(op, "A") == 0) return false;
    if (op[0] == 'R' && op[1] >= '0' && op[1] <= '7' && op[2] == '\0') return false;
    if (op[0] == '#') return false;
    return true;
}

/* 从 spill 内存重载值到临时寄存器，返回基寄存器（或 -2 表示 A） */
static int isel_reload_spill(ISelContext* isel, ValueName val, int size, Instr* ins) {
    if (!isel || !isel->ctx) return -2;
    char* key = int_to_key(val);
    char* var_name = NULL;
    if (isel->ctx->value_to_addr) {
        var_name = (char*)dict_get(isel->ctx->value_to_addr, key);
    }
    free(key);

    if (!var_name) return -2;

    /* 如果累加器已经持有该值，直接返回 A，避免重复加载 */
    if (isel->acc_busy && isel->acc_val == val) {
        return -2;
    }

    /* 如果已经存在映射且不是标记为 spill(-3)，直接返回映射，避免重复重载 */
    if (isel->ctx && isel->ctx->value_to_reg) {
        char* k = int_to_key(val);
        int* existing = (int*)dict_get(isel->ctx->value_to_reg, k);
        free(k);
        if (existing && *existing != -3) return *existing;
    }

    int reg = alloc_temp_reg(isel, val, size);
    const char* ssa = ins ? instr_to_ssa_str(ins) : NULL;

    if (reg >= 0) {
        /* 将重载到的寄存器记录到全局映射，避免后续重复重载 */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = reg;
            char* k = int_to_key(val);
            dict_put(isel->ctx->value_to_reg, k, reg_num);
        }
        /* 低字节：根据符号所在段选择合适的加载指令 */
        const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
        /* 如果在ObjFile中有该符号，使用对应内存空间的加载序列 */
        if (isel->ctx && isel->ctx->obj) {
            /* 查找符号并根据section决定加载方式 */
            SectionKind sym_sec = SEC_DATA;
            for (Iter it = list_iter(isel->ctx->obj->symbols); !iter_end(it);) {
                Symbol *sym = iter_next(&it);
                if (sym && sym->name && var_name && strcmp(sym->name, var_name) == 0) {
                    Section *s = obj_get_section(isel->ctx->obj, sym->section);
                    if (s) sym_sec = s->kind;
                    break;
                }
            }

            if (sym_sec == SEC_XDATA) {
                char dptr_val[256];
                snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                isel_emit(isel, "MOVX", "A", "@DPTR", ssa);
            } else if (sym_sec == SEC_IDATA) {
                isel_emit(isel, "MOV", "R0", var_name, NULL);
                isel_emit(isel, "MOV", "A", "@R0", ssa);
            } else if (sym_sec == SEC_CODE) {
                char dptr_val[256];
                snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                isel_emit(isel, "CLR", "A", NULL, NULL);
                isel_emit(isel, "MOVC", "A", "@A+DPTR", ssa);
            } else {
                isel_emit(isel, "MOV", "A", var_name, ssa);
            }
        } else {
            isel_emit(isel, "MOV", "A", var_name, ssa);
        }
        if (ssa) { free((void*)ssa); ssa = NULL; }
        if (dst_lo && strcmp(dst_lo, "A") != 0) {
            isel_emit(isel, "MOV", dst_lo, "A", NULL);
        }

        if (size == 2) {
            /* 高字节也使用对应的加载序列 */
            if (isel->ctx && isel->ctx->obj) {
                SectionKind sym_sec = SEC_DATA;
                for (Iter it = list_iter(isel->ctx->obj->symbols); !iter_end(it);) {
                    Symbol *sym = iter_next(&it);
                    if (sym && sym->name && var_name && strcmp(sym->name, var_name) == 0) {
                        Section *s = obj_get_section(isel->ctx->obj, sym->section);
                        if (s) sym_sec = s->kind;
                        break;
                    }
                }

                if (sym_sec == SEC_XDATA) {
                    char dptr_val[256];
                    snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
                    isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                    isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
                } else if (sym_sec == SEC_CODE) {
                    char dptr_val[256];
                    snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
                    isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                    isel_emit(isel, "CLR", "A", NULL, NULL);
                    isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
                } else if (sym_sec == SEC_IDATA) {
                    /* idata 高字节通过 R0 指向的地址+1 访问 */
                    char off1[256];
                    snprintf(off1, sizeof(off1), "%s + 1", var_name);
                    isel_emit(isel, "MOV", "R0", off1, NULL);
                    isel_emit(isel, "MOV", "A", "@R0", NULL);
                } else {
                    char var_hi[256];
                    snprintf(var_hi, sizeof(var_hi), "(%s + 1)", var_name);
                    isel_emit(isel, "MOV", "A", var_hi, NULL);
                }
            } else {
                char var_hi[256];
                snprintf(var_hi, sizeof(var_hi), "(%s + 1)", var_name);
                isel_emit(isel, "MOV", "A", var_hi, NULL);
            }

            const char* dst_hi = isel_reg_name(reg);
            if (dst_hi && strcmp(dst_hi, "A") != 0) {
                isel_emit(isel, "MOV", dst_hi, "A", NULL);
            }
        }
        return reg;
    } else {
        /* 无寄存器可用，直接把值加载到 A */
        /* 再次检查累加器，避免重复加载（并发场景） */
        if (isel->acc_busy && isel->acc_val == val) {
            if (ssa) free((void*)ssa);
            return -2;
        }
        isel_emit(isel, "MOV", "A", var_name, ssa);
        if (ssa) free((void*)ssa);

        /* 记录该值现在位于 A（映射 -2），避免后续重复重载 */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = -2;
            char* k = int_to_key(val);
            dict_put(isel->ctx->value_to_reg, k, reg_num);
        }
        isel->acc_busy = true;
        isel->acc_val = val;
        return -2;
    }
}

/* 执行寄存器并行拷贝，避免参数重排时源寄存器被覆盖 */
static void emit_parallel_reg_moves(ISelContext* isel, RegMove* moves, int n, Instr* ins) {
    if (!isel || !moves || n <= 0) return;

    bool done[64] = {0};
    int remaining = n;

    while (remaining > 0) {
        bool progressed = false;

        for (int i = 0; i < n; i++) {
            if (done[i]) continue;

            if (moves[i].dst == moves[i].src) {
                done[i] = true;
                remaining--;
                progressed = true;
                continue;
            }

            bool dst_used_as_src = false;
            for (int j = 0; j < n; j++) {
                if (j == i || done[j]) continue;
                if (moves[j].src == moves[i].dst) {
                    dst_used_as_src = true;
                    break;
                }
            }

            if (!dst_used_as_src) {
                const char* dst = isel_reg_name(moves[i].dst);
                const char* src = (moves[i].src == -2) ? "A" : isel_reg_name(moves[i].src);
                emit_mov(isel, (char*)dst, (char*)src, ins);
                done[i] = true;
                remaining--;
                progressed = true;
            }
        }

        if (progressed) continue;

        /* 存在环，使用A打破 */
        int cyc = -1;
        for (int i = 0; i < n; i++) {
            if (!done[i] && moves[i].src >= 0) {
                cyc = i;
                break;
            }
        }
        if (cyc < 0) break;

        int saved_src = moves[cyc].src;
        emit_mov(isel, "A", (char*)isel_reg_name(saved_src), ins);

        for (int j = 0; j < n; j++) {
            if (!done[j] && moves[j].src == saved_src) {
                moves[j].src = -2;
            }
        }
    }
}

/* 获取值分配的寄存器基址 */
int isel_get_value_reg(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_reg) return -1;
    char* key = int_to_key(val);
    int* reg_ptr = (int*)dict_get(isel->ctx->value_to_reg, key);
    free(key);
    if (reg_ptr) return *reg_ptr;
    return -1;
}

/* 获取值的大小（字节数） */
static int get_value_size(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_type) return 1;
    char* key = int_to_key(val);
    Ctype* type = (Ctype*)dict_get(isel->ctx->value_type, key);
    free(key);
    if (type && type->size > 0) return type->size;
    return 1;  // 默认为单字节
}

static int get_mem_space(Ctype* mem_type) {
    if (!mem_type) return 0;
    return (mem_type->attr >> 7) & 0x7; // ctype_data
}

static bool is_sbit_type(Ctype* mem_type) {
    if (!mem_type) return false;
    CtypeAttr a = get_attr(mem_type->attr);
    return a.ctype_register && mem_type->type == CTYPE_BOOL;
}

static int parse_block_id(const char* label) {
    if (!label) return -1;
    int id = -1;
    if (sscanf(label, "block%d", &id) == 1) return id;
    return -1;
}

static void block_label_name(char* out, size_t out_len, int id) {
    snprintf(out, out_len, "L%d", id);
}

/* 获取值指定字节偏移的寄存器名称 */
const char* isel_get_value_reg_at(ISelContext* isel, ValueName val, int offset) {
    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == -2) return "A";  // 值在累加器中
    if (base_reg < 0) {
        /* 未分配：这表示寄存器分配失败，应该使用累加器或直接操作 */
        if (offset == 0) return "R6";  /* 高字节默认 */
        else return "R7";  /* 低字节默认 */
    }
    if (base_reg + offset < 8) return isel_reg_name(base_reg + offset);
    return isel_reg_name(7);
}

const char* isel_get_lo_reg(ISelContext* isel, ValueName val) {
    int size = get_value_size(isel, val);
    int base_reg = isel_get_value_reg(isel, val);
    
    if (base_reg == -2) return "A";  /* 值在累加器中 */
    if (base_reg < 0) {
        if (base_reg == -3) {
            int r = isel_reload_spill(isel, val, size, NULL);
            if (r >= 0) return isel_reg_name(r + (size == 2 ? 1 : 0));
            return "A";
        }
        return "R7";   /* 默认返回值寄存器 */
    }
    
    if (size == 1) {
        /* 单字节值：直接返回基址寄存器 */
        return isel_reg_name(base_reg);
    } else {
        /* 双字节值：大端模式，低字节在 base_reg+1 */
        return isel_reg_name(base_reg + 1);
    }
}

const char* isel_get_hi_reg(ISelContext* isel, ValueName val) {
    // 高字节总是在基址
    int base_reg = isel_get_value_reg(isel, val);
    int size = get_value_size(isel, val);
    if (base_reg == -3) {
        int r = isel_reload_spill(isel, val, size, NULL);
        if (r >= 0) return isel_reg_name(r);
        return "A";
    }
    return isel_get_value_reg_at(isel, val, 0);
}

/* 为值分配寄存器的安全包装：分配失败时使用累加器 */
static int safe_alloc_reg_for_value(ISelContext* isel, ValueName val, int size) {
    int reg = alloc_reg_for_value(isel, val, size);
    if (reg < 0) {
        /* 寄存器分配失败，将值记录在累加器中 */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = -2;  /* -2 表示值在累加器A中 */
            char* key = int_to_key(val);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
        return -2;  /* 返回-2表示值在A中 */
    }
    return reg;
}

/* 生成新标签 */
char* isel_new_label(ISelContext* isel, const char* prefix) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s_%d", prefix, isel->label_counter++);
    return strdup(buf);
}

/* 发射汇编指令 */
void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2, const char* ssa) {
    if (!isel || !isel->sec) return;
    
    AsmInstr* ins = calloc(1, sizeof(AsmInstr));
    ins->op = strdup(op);
    ins->args = make_list();
    if (arg1) list_push(ins->args, strdup(arg1));
    if (arg2) list_push(ins->args, strdup(arg2));
    if (ssa) ins->ssa = strdup(ssa);
    list_push(isel->sec->asminstrs, ins);
}

/* 发射MOV指令 */
static void emit_mov(ISelContext* isel, const char* dst, const char* src, Instr* ins) {
    if (!dst || !src || strcmp(dst, src) == 0) return;
    /* 如果 src 看起来像一个符号名，且在 ObjFile 中注册，按 section 发射合适的加载序列 */
    if (isel && isel->ctx && isel->ctx->obj) {
        SectionKind sym_sec = SEC_DATA;
        bool found = false;
        for (Iter it = list_iter(isel->ctx->obj->symbols); !iter_end(it);) {
            Symbol *sym = iter_next(&it);
            if (sym && sym->name && strcmp(sym->name, src) == 0) {
                Section *s = obj_get_section(isel->ctx->obj, sym->section);
                if (s) sym_sec = s->kind;
                found = true;
                break;
            }
        }
        if (found) {
            char* ssa = instr_to_ssa_str(ins);
            if (sym_sec == SEC_XDATA) {
                char dptr_val[256];
                snprintf(dptr_val, sizeof(dptr_val), "#%s", src);
                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
                isel_emit(isel, "MOV", dst, "A", ssa);
            } else if (sym_sec == SEC_IDATA) {
                isel_emit(isel, "MOV", "R0", src, NULL);
                isel_emit(isel, "MOV", "A", "@R0", NULL);
                isel_emit(isel, "MOV", dst, "A", ssa);
            } else if (sym_sec == SEC_CODE) {
                char dptr_val[256];
                snprintf(dptr_val, sizeof(dptr_val), "#%s", src);
                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                isel_emit(isel, "CLR", "A", NULL, NULL);
                isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
                isel_emit(isel, "MOV", dst, "A", ssa);
            } else {
                isel_emit(isel, "MOV", dst, src, ssa);
            }
            free(ssa);
            return;
        }
    }

    /* 默认路径：直接发 MOV */
    char* ssa = instr_to_ssa_str(ins);
    isel_emit(isel, "MOV", dst, src, ssa);
    free(ssa);
}

/* 确保值在累加器中 */
void isel_ensure_in_acc(ISelContext* isel, ValueName val) {
    if (!isel || val <= 0) return;
    
    // 已经在A中
    if (isel->acc_busy && isel->acc_val == val) return;
    
    // 从寄存器移动到A
    const char* reg = isel_get_lo_reg(isel, val);
    if (strcmp(reg, "A") != 0) {
        isel_emit(isel, "MOV", "A", reg, NULL);
    }
    
    isel->acc_busy = true;
    isel->acc_val = val;
}

/* 检查是否可以保留在累加器中（下一条指令立即使用） */
bool isel_can_keep_in_acc(ISelContext* isel, Instr* ins, Instr* next) {
    (void)isel;
    if (!ins || !next || ins->dest <= 0) return false;
    
    // 检查下一条指令是否使用当前结果
    if (next->args) {
        for (int i = 0; i < next->args->len; i++) {
            ValueName* p = list_get(next->args, i);
            if (p && *p == ins->dest) return true;
        }
    }
    return false;
}

/* 为值分配寄存器 */
/* alloc_reg_for_value 在 c51_regalloc.c 中提供 */

/* 获取指令源操作数 */
static ValueName get_src1_value(Instr* ins) {
    if (ins && ins->args && ins->args->len > 0) {
        ValueName* p = list_get(ins->args, 0);
        if (p) return *p;
    }
    return -1;
}

static ValueName get_src2_value(Instr* ins) {
    if (ins && ins->args && ins->args->len > 1) {
        ValueName* p = list_get(ins->args, 1);
        if (p) return *p;
    }
    return -1;
}

/* 检查是否为立即数 */
static bool is_imm_operand(Instr* ins, int64_t* out_val) {
    if (ins->labels && ins->labels->len > 0) {
        char* tag = (char*)list_get(ins->labels, 0);
        if (tag && strcmp(tag, "imm") == 0) {
            if (out_val) *out_val = ins->imm.ival;
            return true;
        }
    }
    return false;
}

/* 发射常量加载 */
static void emit_const(ISelContext* isel, Instr* ins) {
    int size = ins->type ? ins->type->size : 1;
    int val = (int)(ins->imm.ival & 0xFFFF);
    
    // 为目标分配寄存器
    int reg = alloc_reg_for_value(isel, ins->dest, size);
    
    if (size == 1) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", val & 0xFF);
        emit_mov(isel, isel_reg_name(reg), imm_str, ins);
    } else if (size == 2) {
        char imm_high[16], imm_low[16];
        snprintf(imm_high, sizeof(imm_high), "#%d", (val >> 8) & 0xFF);
        snprintf(imm_low, sizeof(imm_low), "#%d", val & 0xFF);

        emit_mov(isel, isel_reg_name(reg), imm_high, ins);
        emit_mov(isel, isel_reg_name(reg + 1), imm_low, ins);
    }
}

/* 发射加法 */
static void emit_add(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    
    bool keep_in_acc = isel_can_keep_in_acc(isel, ins, next);
    
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    if (dst_reg < 0) dst_reg = 0;  /* 分配失败，使用R0 */
    
    /* 计算低字节 */
    const char* src1_lo = isel_get_lo_reg(isel, src1);
    emit_mov(isel, "A", (char*)src1_lo, ins);
    
    if (src2_is_imm) {
        int imm_low = (int)(imm_val & 0xFF);
        if (imm_low == 1 && size == 1) {
            isel_emit(isel, "INC", "A", NULL, instr_to_ssa_str(ins));
        } else if (imm_low == 2 && size == 1) {
            isel_emit(isel, "INC", "A", NULL, instr_to_ssa_str(ins));
            isel_emit(isel, "INC", "A", NULL, NULL);
        } else {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", imm_low);
            isel_emit(isel, "ADD", "A", imm_str, instr_to_ssa_str(ins));
        }
    } else {
        ValueName src2 = get_src2_value(ins);
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "ADD", "A", src2_lo, NULL);
    }
    
    /* 立即保存低字节结果 */
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    emit_mov(isel, (char*)dst_lo, "A", NULL);
    
    /* 如果是双字节，处理高字节 */
    if (size == 2) {
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* dst_hi = isel_reg_name(dst_reg);
        
        emit_mov(isel, "A", (char*)src1_hi, NULL);
        
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "ADDC", "A", imm_str, NULL);
        } else {
            ValueName src2 = get_src2_value(ins);
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "ADDC", "A", (char*)src2_hi, NULL);
        }
        
        emit_mov(isel, (char*)dst_hi, "A", NULL);
    }
    
    /* 如果下一条是返回指令，提前把结果放到返回寄存器 R7:R6 */
    if (next && next->op == IROP_RET) {
        const char* ret_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
        const char* ret_hi = isel_reg_name(dst_reg);
        
        if (strcmp(ret_lo, "R7") != 0) {
            emit_mov(isel, "R7", (char*)ret_lo, NULL);
        }
        if (size == 2) {
            if (strcmp(ret_hi, "R6") != 0) {
                emit_mov(isel, "R6", (char*)ret_hi, NULL);
            }
        } else {
            emit_mov(isel, "R6", "#0", NULL);
        }

        /* 同步映射，避免 emit_ret 再次重复搬运 */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = (size == 2) ? 6 : 7; /* int高字节在R6，char在R7 */
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
    }
}

/* 发射按位与 */
static void emit_and(ISelContext* isel, Instr* ins) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    const char* src1_hi = isel_get_hi_reg(isel, src1);

    // 低字节
    emit_mov(isel, "A", (char*)src1_lo, ins);
    if (src2_is_imm) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(imm_val & 0xFF));
        isel_emit(isel, "ANL", "A", imm_str, NULL);
    } else {
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "ANL", "A", (char*)src2_lo, NULL);
    }
    emit_mov(isel, (char*)dst_lo, "A", ins);

    if (size == 2) {
        emit_mov(isel, "A", (char*)src1_hi, ins);
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "ANL", "A", imm_str, NULL);
        } else {
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "ANL", "A", (char*)src2_hi, NULL);
        }
        emit_mov(isel, (char*)dst_hi, "A", ins);
    }
}

/* 发射按位或 */
static void emit_or(ISelContext* isel, Instr* ins) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    const char* src1_hi = isel_get_hi_reg(isel, src1);

    // 低字节
    emit_mov(isel, "A", (char*)src1_lo, ins);
    if (src2_is_imm) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(imm_val & 0xFF));
        isel_emit(isel, "ORL", "A", imm_str, NULL);
    } else {
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "ORL", "A", (char*)src2_lo, NULL);
    }
    emit_mov(isel, (char*)dst_lo, "A", ins);

    if (size == 2) {
        emit_mov(isel, "A", (char*)src1_hi, ins);
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "ORL", "A", imm_str, NULL);
        } else {
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "ORL", "A", (char*)src2_hi, NULL);
        }
        emit_mov(isel, (char*)dst_hi, "A", ins);
    }
}

/* 发射按位异或 */
static void emit_xor(ISelContext* isel, Instr* ins) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    const char* src1_hi = isel_get_hi_reg(isel, src1);

    // 低字节
    emit_mov(isel, "A", (char*)src1_lo, ins);
    if (src2_is_imm) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(imm_val & 0xFF));
        isel_emit(isel, "XRL", "A", imm_str, NULL);
    } else {
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "XRL", "A", (char*)src2_lo, NULL);
    }
    emit_mov(isel, (char*)dst_lo, "A", ins);

    if (size == 2) {
        emit_mov(isel, "A", (char*)src1_hi, ins);
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "XRL", "A", imm_str, NULL);
        } else {
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "XRL", "A", (char*)src2_hi, NULL);
        }
        emit_mov(isel, (char*)dst_hi, "A", ins);
    }
}

/* 发射按位取反 */
static void emit_not(ISelContext* isel, Instr* ins) {
    ValueName src1 = get_src1_value(ins);
    int src_size = get_value_size(isel, src1);  // 源操作数的大小
    int dst_size = ins->type ? ins->type->size : 1;  // 目标操作数的大小

    int reg = safe_alloc_reg_for_value(isel, ins->dest, dst_size);
    
    // 如果寄存器分配成功，设置目标寄存器名
    const char* dst_lo = NULL;
    const char* dst_hi = NULL;
    if (reg >= 0) {
        dst_lo = isel_reg_name(reg + (dst_size == 2 ? 1 : 0));
        dst_hi = isel_reg_name(reg);
    } else if (reg == -2) {
        // 值在A中
        dst_lo = "A";
        dst_hi = NULL;  // 高字节暂时没地方放
    }

    // 直接使用 isel_get_lo_reg/hi_reg，它们会根据值的大小正确处理
    // 注意：这里必须根据源操作数的实际大小来获取寄存器
    int src_reg = isel_get_value_reg(isel, src1);
    const char* src1_lo;
    const char* src1_hi;
    
    if (src_size == 1) {
        // 单字节源：直接使用基址寄存器
        if (src_reg >= 0) {
            src1_lo = isel_reg_name(src_reg);
        } else {
            // 寄存器未分配，使用 isel_get_lo_reg 的默认行为
            src1_lo = isel_get_lo_reg(isel, src1);
        }
        src1_hi = NULL;
    } else {
        // 双字节源：大端模式
        if (src_reg >= 0) {
            src1_lo = isel_reg_name(src_reg + 1);
            src1_hi = isel_reg_name(src_reg);
        } else {
            src1_lo = isel_get_lo_reg(isel, src1);
            src1_hi = isel_get_hi_reg(isel, src1);
        }
    }

    // 低字节
    emit_mov(isel, "A", (char*)src1_lo, ins);
    isel_emit(isel, "CPL", "A", NULL, NULL);
    if (dst_lo) {
        emit_mov(isel, (char*)dst_lo, "A", ins);
    }

    // 高字节（如果目标是双字节且有地方存放）
    if (dst_size == 2 && dst_hi) {
        if (src_size == 2 && src1_hi) {
            // 源也是双字节，取反高字节
            emit_mov(isel, "A", (char*)src1_hi, ins);
            isel_emit(isel, "CPL", "A", NULL, NULL);
        } else {
            // 源是单字节，高字节填充0xFF（因为单字节char被提升为int时高字节为0，取反后为0xFF）
            isel_emit(isel, "MOV", "A", "#0FFH", NULL);
        }
        emit_mov(isel, (char*)dst_hi, "A", ins);
    }
}

/* 发射不等比较（生成 0/1） */
static void emit_ne(ISelContext* isel, Instr* ins) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    char* l_true = isel_new_label(isel, "Lne_true");
    char* l_end = isel_new_label(isel, "Lne_end");
    char lbuf_true[64];
    char lbuf_end[64];
    snprintf(lbuf_true, sizeof(lbuf_true), "%s:", l_true);
    snprintf(lbuf_end, sizeof(lbuf_end), "%s:", l_end);

    if (size == 2) {
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* src1_lo = isel_get_lo_reg(isel, src1);

        emit_mov(isel, "A", (char*)src1_hi, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)((imm_val >> 8) & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_hi, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }

        emit_mov(isel, "A", (char*)src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
    } else {
        const char* src1_lo = isel_get_lo_reg(isel, src1);
        emit_mov(isel, "A", (char*)src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
    }

    isel_emit(isel, "MOV", "A", "#0", NULL);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lbuf_true, NULL, NULL, NULL);
    isel_emit(isel, "MOV", "A", "#1", NULL);
    isel_emit(isel, lbuf_end, NULL, NULL, NULL);

    emit_mov(isel, (char*)dst_lo, "A", ins);
    if (size == 2) {
        emit_mov(isel, (char*)dst_hi, "#00H", ins);
    }

    free(l_true);
    free(l_end);
}

/* 发射逻辑非（生成 0/1） */
static void emit_lnot(ISelContext* isel, Instr* ins) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    char* l_true = isel_new_label(isel, "Lnot_true");
    char* l_end = isel_new_label(isel, "Lnot_end");
    char lbuf_true[64];
    char lbuf_end[64];
    snprintf(lbuf_true, sizeof(lbuf_true), "%s:", l_true);
    snprintf(lbuf_end, sizeof(lbuf_end), "%s:", l_end);

    if (size == 2) {
        const char* hi = isel_get_hi_reg(isel, src);
        const char* lo = isel_get_lo_reg(isel, src);
        emit_mov(isel, "A", (char*)hi, ins);
        isel_emit(isel, "ORL", "A", (char*)lo, NULL);
    } else {
        isel_ensure_in_acc(isel, src);
    }

    // A == 0 -> true
    isel_emit(isel, "JZ", l_true, NULL, NULL);
    isel_emit(isel, "MOV", "A", "#0", NULL);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lbuf_true, NULL, NULL, NULL);
    isel_emit(isel, "MOV", "A", "#1", NULL);
    isel_emit(isel, lbuf_end, NULL, NULL, NULL);

    emit_mov(isel, (char*)dst_lo, "A", ins);
    if (size == 2) {
        emit_mov(isel, (char*)dst_hi, "#0", ins);
    }

    free(l_true);
    free(l_end);
}

/* 发射减法 */
static void emit_sub(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    
    const char* src1_lo = isel_get_lo_reg(isel, src1);
    
    // 分配目标寄存器并保存，以便后续获取高字节
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    
    emit_mov(isel, "A", (char*)src1_lo, ins);
    
    if (src2_is_imm) {
        int imm_low = (int)(imm_val & 0xFF);
        // 优化：-1 使用 DEC A
        if (imm_low == 1 && size == 1) {
            isel_emit(isel, "DEC", "A", NULL, instr_to_ssa_str(ins));
        } 
        // 优化：-2 使用 DEC A; DEC A
        else if (imm_low == 2 && size == 1) {
            isel_emit(isel, "DEC", "A", NULL, instr_to_ssa_str(ins));
            isel_emit(isel, "DEC", "A", NULL, NULL);
        } else {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            ValueName src2 = get_src2_value(ins);
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            isel_emit(isel, "SUBB", "A", (char*)src2_lo, instr_to_ssa_str(ins));
        }
    } else {
        isel_emit(isel, "CLR", "C", NULL, NULL);
        ValueName src2 = get_src2_value(ins);
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "SUBB", "A", (char*)src2_lo, instr_to_ssa_str(ins));
    }
    
    emit_mov(isel, (char*)dst_lo, "A", ins);
    
    if (size == 2) {
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* dst_hi = isel_reg_name(dst_reg);
        
        emit_mov(isel, "A", (char*)src1_hi, ins);
        
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "SUBB", "A", imm_str, NULL);
        } else {
            ValueName src2 = get_src2_value(ins);
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "SUBB", "A", (char*)src2_hi, NULL);
        }
        
        emit_mov(isel, (char*)dst_hi, "A", ins);
    }
    
    /* 如果下一条是返回指令，提前把结果放到返回寄存器 R7:R6 */
    if (next && next->op == IROP_RET) {
        const char* ret_lo = NULL;
        const char* ret_hi = NULL;
        if (dst_reg >= 0) {
            ret_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
            ret_hi = isel_reg_name(dst_reg);
        } else {
            ret_lo = isel_get_lo_reg(isel, ins->dest);
            ret_hi = isel_get_hi_reg(isel, ins->dest);
        }
        if (ret_lo && strcmp(ret_lo, "R7") != 0) {
            emit_mov(isel, "R7", (char*)ret_lo, ins);
        }
        if (size == 2) {
            if (ret_hi && strcmp(ret_hi, "R6") != 0) {
                emit_mov(isel, "R6", (char*)ret_hi, ins);
            }
        } else {
            emit_mov(isel, "R6", "#00H", ins);
        }

        /* 同步映射，避免 emit_ret 再次重复搬运 */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = (size == 2) ? 6 : 7;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
    }
}

/* 发射截断 */
static void emit_trunc(ISelContext* isel, Instr* ins) {
    ValueName src = get_src1_value(ins);
    int src_size = get_value_size(isel, src);
    
    if (src_size == 2) {
        // 从 2字节截断为 1字节：取低字节
        int src_base = isel_get_value_reg(isel, src);  // 获取源的基址寄存器
        if (src_base >= 0) {
            // 低字节在基址+1的位置（大端）
            int lo_reg = src_base + 1;
            
            // 让目标直接使用低字节寄存器
            int* reg_num = malloc(sizeof(int));
            *reg_num = lo_reg;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
            
            // 标记该寄存器被占用
            if (lo_reg < 8) {
                isel->reg_busy[lo_reg] = true;
                isel->reg_val[lo_reg] = ins->dest;
            }
        } else if (src_base == -2) {
            // 源在A中，目标也是A（直接关联到A）
            int* reg_num = malloc(sizeof(int));
            *reg_num = -2;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        } else {
            // 源不在寄存器中，需要分配新寄存器
            int dst_reg = safe_alloc_reg_for_value(isel, ins->dest, 1);
            if (dst_reg >= 0) {
                const char* src_lo = isel_get_lo_reg(isel, src);
                emit_mov(isel, (char*)isel_reg_name(dst_reg), (char*)src_lo, ins);
            }
        }
    } else {
        // 1字节到1字节：直接复用源寄存器
        int* reg_num = malloc(sizeof(int));
        *reg_num = isel_get_value_reg(isel, src);
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
    }
}

/* 发射返回 */
static void emit_ret(ISelContext* isel, Instr* ins) {
    if (ins->args && ins->args->len > 0) {
        ValueName ret_val = *(ValueName*)list_get(ins->args, 0);
        int ret_size = ins->type ? ins->type->size : 1;  // 函数返回类型的大小
        int val_size = get_value_size(isel, ret_val);    // 实际值的大小

        /* 移动低字节到 R7 */
        const char* ret_lo = isel_get_lo_reg(isel, ret_val);
        if (ret_lo && strcmp(ret_lo, "R7") != 0) {
            emit_mov(isel, "R7", (char*)ret_lo, ins);
        }

        /* 处理高字节 */
        if (ret_size == 2) {
            if (val_size == 2) {
                // 2字节值返回：复制高字节
                const char* ret_hi = isel_get_hi_reg(isel, ret_val);
                if (ret_hi && strcmp(ret_hi, "R6") != 0) {
                    emit_mov(isel, "R6", (char*)ret_hi, ins);
                }
            } else {
                // 1字节值扩展为2字节返回：高字节置零
                isel_emit(isel, "MOV", "R6", "#0", NULL);
            }
        }
    }
    
    isel_emit(isel, "RET", NULL, NULL, instr_to_ssa_str(ins));
}

/* 发射存储 */
static void emit_store(ISelContext* isel, Instr* ins) {
    // store ptr, value
    ValueName ptr = -1, val = -1;
    if (ins->args && ins->args->len > 0) {
        ptr = *(ValueName*)list_get(ins->args, 0);
    }
    if (ins->args && ins->args->len > 1) {
        val = *(ValueName*)list_get(ins->args, 1);
    }
    
    // 从 value_to_addr 查找变量名
    const char* var_name = NULL;
    if (isel->ctx && isel->ctx->value_to_addr) {
        char* key = int_to_key(ptr);
        var_name = (const char*)dict_get(isel->ctx->value_to_addr, key);
        free(key);
    }
    
    const char* label = NULL;
    if (!var_name && ins->labels && ins->labels->len > 0) {
        label = list_get(ins->labels, 0);
        if (label && label[0] == '@') {
            var_name = label + 1;
        } else {
            var_name = label;
        }
    }
    
    if (!var_name) return;

    // 处理直接常量存储（labels[0] 以 @ 开头，args 可能被清空）
    if (label && label[0] == '@' && (!ins->args || ins->args->len == 0)) {
        if (is_sbit_type(ins->mem_type)) {
            if (ins->imm.ival) {
                isel_emit(isel, "SETB", (char*)var_name, NULL, instr_to_ssa_str(ins));
            } else {
                isel_emit(isel, "CLR", (char*)var_name, NULL, instr_to_ssa_str(ins));
            }
        } else {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)(ins->imm.ival & 0xFF));
            isel_emit(isel, "MOV", (char*)var_name, imm_str, instr_to_ssa_str(ins));
        }
        return;
    }
    
    // 获取内存空间类型 (ctype_data 在 bit 7-9)
    int space = get_mem_space(ins->mem_type);

    /* 如果 var_name 是在ObjFile中注册的spill符号，则优先使用符号所在段决定内存空间 */
    if (var_name && isel->ctx && isel->ctx->obj) {
        for (Iter it = list_iter(isel->ctx->obj->symbols); !iter_end(it);) {
            Symbol *sym = iter_next(&it);
            if (sym && sym->name && strcmp(sym->name, var_name) == 0) {
                Section *s = obj_get_section(isel->ctx->obj, sym->section);
                if (s) {
                    if (s->kind == SEC_XDATA) space = 4;
                    else if (s->kind == SEC_IDATA) space = 2;
                    else if (s->kind == SEC_CODE) space = 6;
                    else space = 1;
                }
                break;
            }
        }
    }
    
    // 获取值的寄存器
    const char* val_reg = isel_get_lo_reg(isel, val);
    
    // 先加载值到累加器（如果还没在累加器中）
    if (strcmp(val_reg, "A") != 0) {
        isel_emit(isel, "MOV", "A", (char*)val_reg, NULL);
    }
    
    // sbit 写入：MOV C, ACC.0; MOV bit, C
    if (is_sbit_type(ins->mem_type)) {
        isel_emit(isel, "MOV", "C", "ACC.0", NULL);
        isel_emit(isel, "MOV", (char*)var_name, "C", instr_to_ssa_str(ins));
        return;
    }

    // 根据内存空间生成不同的指令
    if (space == 4) {
        // xdata (4): 使用 MOVX @DPTR
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "MOVX", "@DPTR", "A", instr_to_ssa_str(ins));
    } else if (space == 2) {
        // idata (2): 使用 MOV @Ri
        isel_emit(isel, "MOV", "R0", var_name, NULL);
        isel_emit(isel, "MOV", "@R0", "A", instr_to_ssa_str(ins));
    } else {
        // data (1) 或默认 (0): 使用 MOV direct
        isel_emit(isel, "MOV", (char*)var_name, "A", instr_to_ssa_str(ins));
    }
}

/* 发射地址获取 */
static void emit_addr(ISelContext* isel, Instr* ins) {
    const char* var_name = NULL;
    if (ins->labels && ins->labels->len > 0) {
        var_name = list_get(ins->labels, 0);
    }
    
    if (!var_name) return;
    
    // 记录地址到变量名的映射
    if (isel->ctx && isel->ctx->value_to_addr) {
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_addr, key, strdup(var_name));
        // key 已被 dict 接管
    }
    
    // DATA/IDATA区（地址<256）使用直接寻址，不生成指令
    // 对于 XDATA/CODE 区需要生成 MOV 指令加载地址到寄存器
}

/* 发射加载 */
static void emit_load(ISelContext* isel, Instr* ins) {
    // load ptr
    ValueName ptr = -1;
    if (ins->args && ins->args->len > 0) {
        ptr = *(ValueName*)list_get(ins->args, 0);
    }
    
    // 从 value_to_addr 查找变量名
    const char* var_name = NULL;
    if (isel->ctx && isel->ctx->value_to_addr && ptr > 0) {
        char* key = int_to_key(ptr);
        var_name = (const char*)dict_get(isel->ctx->value_to_addr, key);
        free(key);
    }
    
    // 如果没有通过 ptr 找到，尝试从 labels 获取
    if (!var_name && ins->labels && ins->labels->len > 0) {
        const char* label = list_get(ins->labels, 0);
        if (label && label[0] == '@') var_name = label + 1;
        else var_name = label;
    }
    
    if (!var_name) return;
    
    // 获取内存空间类型 (ctype_data 在 bit 7-9)
    int space = get_mem_space(ins->mem_type);
    
    int size = ins->type ? ins->type->size : 1;
    int reg = safe_alloc_reg_for_value(isel, ins->dest, size);
    
    // sbit 读取：MOV C, bit; CLR A; RLC A
    if (is_sbit_type(ins->mem_type)) {
        isel_emit(isel, "MOV", "C", (char*)var_name, instr_to_ssa_str(ins));
        isel_emit(isel, "CLR", "A", NULL, NULL);
        isel_emit(isel, "RLC", "A", NULL, NULL);
    } else
    // 根据内存空间生成不同的加载指令
    if (space == 4) {
        // xdata (4): 使用 MOVX A, @DPTR
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "MOVX", "A", "@DPTR", instr_to_ssa_str(ins));
    } else if (space == 6) {
        // code (6): 使用 MOVC A, @A+DPTR
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "CLR", "A", NULL, NULL);
        isel_emit(isel, "MOVC", "A", "@A+DPTR", instr_to_ssa_str(ins));
    } else if (space == 2) {
        // idata (2): 使用 MOV A, @Ri
        isel_emit(isel, "MOV", "R0", var_name, NULL);
        isel_emit(isel, "MOV", "A", "@R0", instr_to_ssa_str(ins));
    } else {
        // data (1) 或默认 (0): 使用 MOV A, direct
        isel_emit(isel, "MOV", "A", (char*)var_name, instr_to_ssa_str(ins));
    }
    
    // 将加载的值从A保存到分配的寄存器（仅当reg >= 0时）
    // 当reg == -2时值已经在A中，不需要额外的MOV
    if (reg >= 0) {
        const char* dst_reg = isel_reg_name(reg + (size == 2 ? 1 : 0));
        if (dst_reg && strcmp(dst_reg, "A") != 0) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "MOV", dst_reg, "A", ssa);
            free(ssa);
        }
    }
    
    if (size == 2 && reg >= 0) {
        // 高字节处理
        if (space == 4) {
            // xdata
            char dptr_val[256];
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
        } else if (space == 6) {
            // code
            char dptr_val[256];
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            isel_emit(isel, "CLR", "A", NULL, NULL);
            isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
        } else {
            char source_hi[256];
            snprintf(source_hi, sizeof(source_hi), "(_%s + 1)", var_name);
            isel_emit(isel, "MOV", "A", source_hi, NULL);
        }
        const char* dst_reg_hi = isel_reg_name(reg);
        if (dst_reg_hi && strcmp(dst_reg_hi, "A") != 0) {
            isel_emit(isel, "MOV", dst_reg_hi, "A", NULL);
        }
    }
}

/* 发射无条件跳转 */
static void emit_jmp(ISelContext* isel, Instr* ins) {
    if (!ins->labels || ins->labels->len < 1) return;
    const char* lbl = (const char*)list_get(ins->labels, 0);
    int id = parse_block_id(lbl);
    if (id < 0) return;
    char target[32];
    block_label_name(target, sizeof(target), id);
    isel_emit(isel, "SJMP", target, NULL, instr_to_ssa_str(ins));
}

/* 发射条件分支 */
static void emit_br(ISelContext* isel, Instr* ins) {
    if (!ins->args || ins->args->len < 1) return;
    if (!ins->labels || ins->labels->len < 2) return;

    ValueName cond = *(ValueName*)list_get(ins->args, 0);
    const char* lbl_t = (const char*)list_get(ins->labels, 0);
    const char* lbl_f = (const char*)list_get(ins->labels, 1);
    int id_t = parse_block_id(lbl_t);
    int id_f = parse_block_id(lbl_f);
    if (id_t < 0 || id_f < 0) return;

    char target_t[32];
    char target_f[32];
    block_label_name(target_t, sizeof(target_t), id_t);
    block_label_name(target_f, sizeof(target_f), id_f);

    int size = get_value_size(isel, cond);
    if (size == 2) {
        const char* hi = isel_get_hi_reg(isel, cond);
        const char* lo = isel_get_lo_reg(isel, cond);
        if (hi && strcmp(hi, "A") != 0) isel_emit(isel, "MOV", "A", hi, NULL);
        if (lo) isel_emit(isel, "ORL", "A", lo, NULL);
    } else {
        isel_ensure_in_acc(isel, cond);
    }

    // A != 0 -> true
    isel_emit(isel, "JNZ", target_t, NULL, instr_to_ssa_str(ins));
    isel_emit(isel, "SJMP", target_f, NULL, NULL);
}

/* 单条指令选择 */
void isel_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins) return;
    
    // 如果指令有类型信息且产生了目标值，记录类型
    if (ins->dest > 0 && ins->type && isel->ctx && isel->ctx->value_type) {
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_type, key, ins->type);
        // key 被 dict 接管，不需要 free
    }
    
    switch (ins->op) {
        case IROP_NOP:
            break;
        case IROP_CONST:
            emit_const(isel, ins);
            break;
        case IROP_PARAM:
            // 参数寄存器已在函数初始化时分配
            break;
        case IROP_ADD:
            emit_add(isel, ins, next);
            break;
        case IROP_SUB:
            emit_sub(isel, ins, next);
            break;
        case IROP_AND:
            emit_and(isel, ins);
            break;
        case IROP_OR:
            emit_or(isel, ins);
            break;
        case IROP_XOR:
            emit_xor(isel, ins);
            break;
        case IROP_NOT:
            emit_not(isel, ins);
            break;
        case IROP_NE:
            emit_ne(isel, ins);
            break;
        case IROP_LNOT:
            emit_lnot(isel, ins);
            break;
        case IROP_TRUNC:
            emit_trunc(isel, ins);
            break;
        case IROP_RET:
            emit_ret(isel, ins);
            break;
        case IROP_STORE:
            emit_store(isel, ins);
            break;
        case IROP_LOAD:
            emit_load(isel, ins);
            break;
        case IROP_JMP:
            emit_jmp(isel, ins);
            break;
        case IROP_BR:
            emit_br(isel, ins);
            break;
        case IROP_ADDR:
            emit_addr(isel, ins);
            break;
        case IROP_ASM:
            if (ins->labels && ins->labels->len > 0) {
                char* asm_text = list_get(ins->labels, 0);
                isel_emit(isel, "; ASM", NULL, asm_text, NULL);
            }
            break;
        case IROP_CALL: {
            if (!ins->labels || ins->labels->len < 1) break;
            const char* fname = list_get(ins->labels, 0);

            // 布置参数到约定寄存器
            RegMove moves[64];
            int move_count = 0;
            for (int k = 0; ins->args && k < ins->args->len; k++) {
                ValueName v = *(ValueName*)list_get(ins->args, k);
                char* key = int_to_key(v);
                Ctype* t = NULL;
                if (isel->ctx && isel->ctx->value_type) {
                    t = (Ctype*)dict_get(isel->ctx->value_type, key);
                }
                free(key);
                int size = t ? t->size : 1;

                if (size == 1) {
                    if (k >= 6) continue;
                    int targ = param_regs_char[k];
                    const char* src_lo = isel_get_lo_reg(isel, v);
                    /* 如果值被spill（通过 value_to_reg 或 value_to_addr 标记），优先重载到临时寄存器 */
                    if (isel_get_value_reg(isel, v) == -3) {
                        int r = isel_reload_spill(isel, v, 1, ins);
                        if (r >= 0) src_lo = isel_reg_name(r);
                        else src_lo = "A";
                    } else if (isel->ctx && isel->ctx->value_to_addr) {
                        char* ktmp = int_to_key(v);
                        const char* sym = (const char*)dict_get(isel->ctx->value_to_addr, ktmp);
                        free(ktmp);
                        if (sym) {
                            int r = isel_reload_spill(isel, v, 1, ins);
                            if (r >= 0) src_lo = isel_reg_name(r);
                            else src_lo = "A";
                        }
                    }
                    const char* dst = isel_reg_name(targ);
                    int src_reg = reg_index_from_name(src_lo);
                    /* 如果源是内存/符号（非寄存器/立即数），优先通过 reload 重载到寄存器或 A */
                    if (src_reg < 0 && src_lo && is_memory_operand_local(src_lo)) {
                        int r = isel_reload_spill(isel, v, 1, ins);
                        if (r >= 0) {
                            src_lo = isel_reg_name(r);
                            src_reg = r;
                        } else {
                            src_lo = "A";
                            src_reg = -2; /* 表示 A */
                        }
                    }

                    if (src_reg >= 0) {
                        if (move_count < 64) {
                            moves[move_count++] = (RegMove){.dst = targ, .src = src_reg};
                        }
                    } else if (src_lo && strcmp(src_lo, dst) != 0) {
                        emit_mov(isel, (char*)dst, (char*)src_lo, ins);
                    }
                } else {
                    if (k >= 3) continue;
                    int targ_hi = param_regs_int_h[k];
                    int targ_lo = param_regs_int_l[k];
                    const char* src_hi = isel_get_hi_reg(isel, v);
                    const char* src_lo = isel_get_lo_reg(isel, v);
                    /* 对被 spill 的双字值，或在 value_to_addr 中有符号的值，先重载到临时寄存器 */
                    if (isel_get_value_reg(isel, v) == -3) {
                        int r = isel_reload_spill(isel, v, 2, ins);
                        if (r >= 0) {
                            src_hi = isel_reg_name(r);
                            src_lo = isel_reg_name(r + 1);
                        } else {
                            src_hi = "A"; src_lo = "A";
                        }
                    } else if (isel->ctx && isel->ctx->value_to_addr) {
                        char* ktmp = int_to_key(v);
                        const char* sym = (const char*)dict_get(isel->ctx->value_to_addr, ktmp);
                        free(ktmp);
                        if (sym) {
                            int r = isel_reload_spill(isel, v, 2, ins);
                            if (r >= 0) {
                                src_hi = isel_reg_name(r);
                                src_lo = isel_reg_name(r + 1);
                            } else {
                                src_hi = "A"; src_lo = "A";
                            }
                        }
                    }
                    const char* dst_hi = isel_reg_name(targ_hi);
                    const char* dst_lo = isel_reg_name(targ_lo);
                    int src_hi_reg = reg_index_from_name(src_hi);
                    int src_lo_reg = reg_index_from_name(src_lo);

                    /* 如果任一半字是内存/符号，先重载整个 value 到临时寄存器 */
                    if ((src_hi_reg < 0 && src_hi && is_memory_operand_local(src_hi)) ||
                        (src_lo_reg < 0 && src_lo && is_memory_operand_local(src_lo))) {
                        int r = isel_reload_spill(isel, v, 2, ins);
                        if (r >= 0) {
                            src_hi = isel_reg_name(r);
                            src_lo = isel_reg_name(r + 1);
                            src_hi_reg = r;
                            src_lo_reg = r + 1;
                        } else {
                            src_hi = "A"; src_lo = "A";
                            src_hi_reg = -2; src_lo_reg = -2;
                        }
                    }

                    if (src_hi_reg >= 0) {
                        if (move_count < 64) {
                            moves[move_count++] = (RegMove){.dst = targ_hi, .src = src_hi_reg};
                        }
                    } else if (src_hi && strcmp(src_hi, dst_hi) != 0) {
                        emit_mov(isel, (char*)dst_hi, (char*)src_hi, ins);
                    }

                    if (src_lo_reg >= 0) {
                        if (move_count < 64) {
                            moves[move_count++] = (RegMove){.dst = targ_lo, .src = src_lo_reg};
                        }
                    } else if (src_lo && strcmp(src_lo, dst_lo) != 0) {
                        emit_mov(isel, (char*)dst_lo, (char*)src_lo, ins);
                    }
                }
            }

            /* 统一执行寄存器重排，避免覆盖 */
            emit_parallel_reg_moves(isel, moves, move_count, ins);

            // 发出调用
            char callee[256];
            snprintf(callee, sizeof(callee), "_%s", fname);
            isel_emit(isel, "LCALL", callee, NULL, instr_to_ssa_str(ins));

            // 将返回值（如果有）分配到目标寄存器
            if (ins->dest > 0) {
                int size = ins->type ? ins->type->size : 1;

                /*
                 * 优化: 如果紧接着的下一条指令是返回，并且该返回返回的正是
                 * 本次调用的结果（例如 pattern: call; ret v），则无需把
                 * R7:R6 的返回值先拷贝到临时寄存器再在 emit_ret 中拷贝回 R7:R6。
                 * 直接让 emit_ret 从 R7:R6 读取并返回，避免多余的 MOV 指令。
                 */
                bool skip_copy_back = false;
                if (next && next->op == IROP_RET && next->args && next->args->len > 0) {
                    ValueName ret_arg = *(ValueName*)list_get(next->args, 0);
                    if (ret_arg == ins->dest) {
                        skip_copy_back = true;
                    }
                }

                if (!skip_copy_back) {
                    int reg = alloc_reg_for_value(isel, ins->dest, size);
                    if (size == 1) {
                        const char* lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
                        if (strcmp("R7", lo) != 0) emit_mov(isel, (char*)lo, "R7", ins);
                    } else if (size == 2) {
                        const char* lo = isel_reg_name(reg + 1);
                        const char* hi = isel_reg_name(reg);
                        if (strcmp("R7", lo) != 0) emit_mov(isel, (char*)lo, "R7", ins);
                        if (strcmp("R6", hi) != 0) emit_mov(isel, (char*)hi, "R6", ins);
                    }
                }
            }
        } break;
        default:
            break;
    }
}

/* 基本块指令选择 */
void isel_block(ISelContext* isel, Block* block) {
    if (!isel || !block || !block->instrs) return;
    
    // 输出基本块标签
    if (block->id > 0) {
        char label[32];
        snprintf(label, sizeof(label), "L%d:", block->id);
        isel_emit(isel, label, NULL, NULL, NULL);
    }
    
    // 预分析：将指令转为数组以便查看下一条
    int num_instrs = block->instrs->len;
    Instr** instrs = malloc(sizeof(Instr*) * num_instrs);
    int idx = 0;
    for (Iter it = list_iter(block->instrs); !iter_end(it);) {
        instrs[idx++] = iter_next(&it);
    }
    
    // 逐条处理指令
    for (int i = 0; i < num_instrs; i++) {
        Instr* next = (i + 1 < num_instrs) ? instrs[i + 1] : NULL;
        isel_instr(isel, instrs[i], next);
    }
    
    free(instrs);
}

/* 为参数分配寄存器 */
/* alloc_param_regs 在 c51_regalloc.c 中提供 */

/* 函数指令选择主入口 */
void isel_function(C51GenContext* ctx, Func* func) {
    if (!ctx || !func) return;

    /* 每个函数独立寄存器分配表，避免跨函数污染 */
    if (ctx->value_to_reg) {
        dict_free(ctx->value_to_reg, free);
        ctx->value_to_reg = make_dict(NULL);
    }
    
    // 创建代码段
    int sec_idx = obj_add_section(ctx->obj, "?PR?", SEC_CODE, 0, 1);
    Section* sec = obj_get_section(ctx->obj, sec_idx);
    
    // 添加函数符号
    int flags = SYM_FLAG_GLOBAL;
    obj_add_symbol(ctx->obj, func->name, SYM_FUNC, sec_idx, sec->size, 0, flags);
    
    ctx->current_func = func;
    
    // 初始化指令选择上下文
    ISelContext isel = {0};
    isel.ctx = ctx;
    isel.sec = sec;
    isel.label_counter = 0;
    
    // 初始化寄存器状态
    for (int i = 0; i < 8; i++) {
        isel.reg_val[i] = -1;
    }
    
    // 输出函数标签
    char label[256];
    snprintf(label, sizeof(label), "_%s:", func->name);
    isel_emit(&isel, label, NULL, NULL, NULL);
    
    // 第一步：为参数分配寄存器
    alloc_param_regs(&isel, func);

    /* 第二步：线性扫描全局分配（Keil约定友好） */
    LinearScanContext* lsc = linscan_create();
    linscan_compute_intervals(lsc, func, ctx);
    linscan_allocate(lsc, ctx);
    
    // 处理每个基本块
    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }
    
    /* 清理线性扫描分配器 */
    linscan_destroy(lsc);
}
