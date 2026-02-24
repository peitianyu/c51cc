#include "c51_isel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 寄存器分配相关接口在 c51_regalloc.c 中实现 */
#include "c51_regalloc.h"

/* 辅助函数：将整数键转换为字符串 */
char* int_to_key(int n) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", n);
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

/* 获取值指定字节偏移的寄存器名称 */
const char* isel_get_value_reg_at(ISelContext* isel, ValueName val, int offset) {
    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == -2) return "A";  // 值在累加器中
    if (base_reg < 0) return (offset == 0) ? "R6" : "R7";
    if (base_reg + offset < 8) return isel_reg_name(base_reg + offset);
    return isel_reg_name(7);
}

const char* isel_get_lo_reg(ISelContext* isel, ValueName val) {
    int size = get_value_size(isel, val);
    if (size == 1) {
        // 单字节值：直接返回基址寄存器
        int base_reg = isel_get_value_reg(isel, val);
        if (base_reg == -2) return "A";
        if (base_reg < 0) return "R7";  // 默认返回值寄存器
        return isel_reg_name(base_reg);
    }
    // 双字节值：大端，低字节在+1位置
    return isel_get_value_reg_at(isel, val, 1);
}

const char* isel_get_hi_reg(ISelContext* isel, ValueName val) {
    // 高字节总是在基址
    return isel_get_value_reg_at(isel, val, 0);
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
        snprintf(imm_str, sizeof(imm_str), "#%02XH", val & 0xFF);
        emit_mov(isel, isel_reg_name(reg), imm_str, ins);
    } else if (size == 2) {
        char imm_high[16], imm_low[16];
        snprintf(imm_high, sizeof(imm_high), "#%02XH", (val >> 8) & 0xFF);
        snprintf(imm_low, sizeof(imm_low), "#%02XH", val & 0xFF);

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
    
    const char* src1_lo = isel_get_lo_reg(isel, src1);
    
    bool keep_in_acc = isel_can_keep_in_acc(isel, ins, next);
    
    // 低字节相加
    isel_ensure_in_acc(isel, src1);
    
    if (src2_is_imm) {
        int imm_low = (int)(imm_val & 0xFF);
        // 优化：+1 使用 INC A
        if (imm_low == 1 && size == 1) {
            isel_emit(isel, "INC", "A", NULL, instr_to_ssa_str(ins));
        } 
        // 优化：+2 使用 INC A; INC A
        else if (imm_low == 2 && size == 1) {
            isel_emit(isel, "INC", "A", NULL, instr_to_ssa_str(ins));
            isel_emit(isel, "INC", "A", NULL, NULL);
        } 
        else {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", imm_low);
            isel_emit(isel, "ADD", "A", imm_str, instr_to_ssa_str(ins));
        }
    } else {
        ValueName src2 = get_src2_value(ins);
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "ADD", "A", src2_lo, NULL);
    }
    
    int dst_reg = -1;
    if (keep_in_acc) {
        // 如果是单字节值，可以保留在累加器中
        if (size == 1) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = -2;  // -2 表示在累加器中
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
            isel->acc_busy = true;
            isel->acc_val = ins->dest;
        } else {
            // 对于 2 字节的值，仍然为目标分配寄存器并把低字节存回，
            // 以避免后续高字节计算覆盖低字节
            dst_reg = alloc_reg_for_value(isel, ins->dest, size);
            const char* dst_lo = isel_reg_name(dst_reg + 1);
            emit_mov(isel, (char*)dst_lo, "A", ins);
        }
    } else {
        // 只有不保留在累加器时才分配寄存器
        dst_reg = alloc_reg_for_value(isel, ins->dest, size);
        const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
        emit_mov(isel, (char*)dst_lo, "A", ins);
    }
    
    if (size == 2) {
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* dst_hi = NULL;
        if (dst_reg >= 0) {
            dst_hi = isel_reg_name(dst_reg);
        } else {
            dst_hi = isel_reg_name(isel_get_value_reg(isel, ins->dest));
        }

        emit_mov(isel, "A", (char*)src1_hi, ins);
        
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "ADDC", "A", imm_str, NULL);
        } else {
            ValueName src2 = get_src2_value(ins);
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "ADDC", "A", (char*)src2_hi, NULL);
        }
        
        emit_mov(isel, (char*)dst_hi, "A", ins);
    }

    /* 如果下一条是返回指令，提前把结果放到返回寄存器 R7:R6 */
    if (next && next->op == IROP_RET) {
        const char* ret_lo = NULL;
        const char* ret_hi = NULL;
        if (dst_reg >= 0) {
            ret_lo = isel_reg_name(dst_reg + 1);
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
            emit_mov(isel, "R6", "#0", ins);
        }
    }
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
        } 
        else {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", imm_low);
            isel_emit(isel, "SUBB", "A", imm_str, instr_to_ssa_str(ins));
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
            ret_lo = isel_reg_name(dst_reg + 1);
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
            emit_mov(isel, "R6", "#0", ins);
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
        } else {
            // 源不在寄存器中，需要分配新寄存器
            int dst_reg = alloc_reg_for_value(isel, ins->dest, 1);
            const char* src_lo = isel_get_lo_reg(isel, src);
            emit_mov(isel, (char*)isel_reg_name(dst_reg), (char*)src_lo, ins);
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
    
    if (!var_name && ins->labels && ins->labels->len > 0) {
        var_name = list_get(ins->labels, 0);
    }
    
    if (!var_name) return;
    
    // 获取值的寄存器
    const char* val_reg = isel_get_lo_reg(isel, val);
    
    // 先加载值到累加器（如果还没在累加器中）
    if (strcmp(val_reg, "A") != 0) {
        isel_emit(isel, "MOV", "A", (char*)val_reg, NULL);
    }
    
    // 直接使用变量名，不添加下划线前缀
    isel_emit(isel, "MOV", (char*)var_name, "A", instr_to_ssa_str(ins));
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
        var_name = list_get(ins->labels, 0);
    }
    
    if (!var_name) return;
    
    int size = ins->type ? ins->type->size : 1;
    int reg = alloc_reg_for_value(isel, ins->dest, size);
    
    // 加载低字节（或单字节）
    isel_emit(isel, "MOV", "A", (char*)var_name, instr_to_ssa_str(ins));
    emit_mov(isel, (char*)isel_reg_name(reg + (size == 2 ? 1 : 0)), "A", ins);
    
    if (size == 2) {
        // 高字节处理
        char source_hi[256];
        snprintf(source_hi, sizeof(source_hi), "(_%s + 1)", var_name);
        isel_emit(isel, "MOV", "A", source_hi, NULL);
        emit_mov(isel, (char*)isel_reg_name(reg), "A", ins);
    }
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
                    const char* dst = isel_reg_name(targ);
                    if (src_lo && strcmp(src_lo, dst) != 0) {
                        emit_mov(isel, (char*)dst, (char*)src_lo, ins);
                    }
                } else {
                    if (k >= 3) continue;
                    int targ_hi = param_regs_int_h[k];
                    int targ_lo = param_regs_int_l[k];
                    const char* src_hi = isel_get_hi_reg(isel, v);
                    const char* src_lo = isel_get_lo_reg(isel, v);
                    const char* dst_hi = isel_reg_name(targ_hi);
                    const char* dst_lo = isel_reg_name(targ_lo);
                    if (src_hi && strcmp(src_hi, dst_hi) != 0) emit_mov(isel, (char*)dst_hi, (char*)src_hi, ins);
                    if (src_lo && strcmp(src_lo, dst_lo) != 0) emit_mov(isel, (char*)dst_lo, (char*)src_lo, ins);
                }
            }

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
    
    // 为参数分配寄存器
    alloc_param_regs(&isel, func);
    
    // 处理每个基本块
    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }
}
