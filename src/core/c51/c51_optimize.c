#include "c51_optimize.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 * 基本操作数/指令类型判断
 * ============================================================ */

/* R0-R7 寄存器快速检查 */
#define IS_RX(op) ((op) && (op)[0]=='R' && (op)[1]>='0' && (op)[1]<='7' && (op)[2]=='\0')

static bool operands_equal(const char* op1, const char* op2) {
    if (!op1 || !op2) return false;
    return strcmp(op1, op2) == 0;
}

static const char* get_operand(AsmInstr* ins, int index) {
    if (!ins || !ins->args || index >= ins->args->len) return NULL;
    return (const char*)list_get(ins->args, index);
}

static bool is_mov(AsmInstr* ins) {
    return ins && ins->op && strcmp(ins->op, "MOV") == 0;
}

static bool is_label_instr(AsmInstr* ins) {
    if (!ins || !ins->op) return false;
    size_t len = strlen(ins->op);
    return len > 0 && ins->op[len - 1] == ':';
}

/* 编译器生成的本地标签：L 开头 + ':' 结尾（合并原 is_local_numeric_label 和 is_compiler_local_label） */
static bool is_local_label(const char* op) {
    if (!op) return false;
    size_t len = strlen(op);
    return len >= 2 && op[0] == 'L' && op[len - 1] == ':';
}

static bool is_control_transfer_instr(AsmInstr* ins) {
    if (!ins || !ins->op) return false;
    const char* op = ins->op;
    return strcmp(op, "SJMP") == 0 || strcmp(op, "AJMP") == 0 ||
           strcmp(op, "LJMP") == 0 || strcmp(op, "JMP")  == 0 ||
           strcmp(op, "JC")   == 0 || strcmp(op, "JNC")  == 0 ||
           strcmp(op, "JZ")   == 0 || strcmp(op, "JNZ")  == 0 ||
           strcmp(op, "CJNE") == 0 || strcmp(op, "DJNZ") == 0 ||
           strcmp(op, "JB")   == 0 || strcmp(op, "JNB")  == 0 ||
           strcmp(op, "JBC")  == 0 || strcmp(op, "RET")  == 0 ||
           strcmp(op, "RETI") == 0 || strcmp(op, "ACALL")== 0 ||
           strcmp(op, "LCALL")== 0 || strcmp(op, "CALL") == 0;
}

static bool is_basic_block_barrier(AsmInstr* ins) {
    return is_label_instr(ins) || is_control_transfer_instr(ins);
}

/* 前向声明：操作数类型检查 */
static bool is_register_operand(const char* op);
static bool is_immediate_operand(const char* op);
static bool is_memory_operand(const char* op);

static bool reg_used_in_instr(AsmInstr* ins, const char* reg) {
    if (!ins || !reg || !ins->args) return false;
    for (int i = 0; i < ins->args->len; i++) {
        const char* arg = (const char*)list_get(ins->args, i);
        if (arg && strcmp(arg, reg) == 0) return true;
    }
    return false;
}

static bool operand_reads_reg(const char* arg, const char* reg) {
    if (!arg || !reg) return false;
    if (operands_equal(arg, reg)) return true;
    if (arg[0] == '@') return operands_equal(arg + 1, reg);
    return false;
}

static bool is_indirect_operand(const char* op) {
    return op && op[0] == '@';
}

/* 将 "Lxxx:" 指令的操作码转为裸标签名写入 buf，成功返回 true */
static bool get_label_name(AsmInstr* ins, char* buf, size_t buf_size) {
    if (!ins || !ins->op || !buf || buf_size == 0) return false;
    size_t len = strlen(ins->op);
    if (len == 0 || ins->op[len - 1] != ':' || len >= buf_size) return false;
    memcpy(buf, ins->op, len - 1);
    buf[len - 1] = '\0';
    return true;
}

static bool operand_references_label(const char* arg, const char* label) {
    const char *comma;

    if (!arg || !label) return false;
    while (*arg == ' ' || *arg == '\t') arg++;
    if (*arg == '#') arg++;  /* 跳过立即数前缀 '#'，如 MOV DPTR, #LabelName */
    if (strcmp(arg, label) == 0) return true;

    comma = strrchr(arg, ',');
    if (!comma) return false;
    comma++;
    while (*comma == ' ' || *comma == '\t') comma++;
    if (*comma == '#') comma++;  /* 同样跳过逗号后操作数的 '#' 前缀 */
    return strcmp(comma, label) == 0;
}

static bool label_is_referenced(List* instrs, const char* label) {
    if (!instrs || !label) return false;
    for (int i = 0; i < instrs->len; i++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, i);
        if (!ins || !ins->args) continue;
        for (int j = 0; j < ins->args->len; j++) {
            const char* arg = (const char*)list_get(ins->args, j);
            if (operand_references_label(arg, label)) return true;
        }
    }
    return false;
}

/* 删除指令 */
static void remove_instr(List* instrs, int index) {
    if (!instrs || index < 0 || index >= instrs->len) return;
    ListNode* node = instrs->head;
    for (int i = 0; i < index; i++) node = node->next;
    if (!node) return;
    if (node->prev) node->prev->next = node->next;
    else            instrs->head     = node->next;
    if (node->next) node->next->prev = node->prev;
    else            instrs->tail     = node->prev;
    instrs->len--;
    free(node);
}

/* 窥孔优化：MOV A, x; MOV y, A -> MOV y, x (如果之后不立即使用A) */
static int peephole_mov_chain(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);

    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // MOV A, x; MOV y, A -> MOV y, x; (remove MOV A, x)
    // Works for: x = register, immediate, or direct IDATA address (not indirect)
    // y must be a register (not A, not indirect)
    if (operands_equal(dst1, "A") && operands_equal(src2, "A") && 
        is_register_operand(dst2) && !operands_equal(dst2, "A") &&
        src1 && !is_indirect_operand(src1)) {
        
        // Check if A is used by the next instruction
        bool a_used_next = false;
        if (start + 2 < instrs->len) {
            AsmInstr* ins3 = (AsmInstr*)list_get(instrs, start + 2);
            if (ins3 && !is_mov(ins3)) {
                a_used_next = reg_used_in_instr(ins3, "A");
            }
        }
        
        // If A is not immediately needed, optimize: MOV y, x (remove MOV A, x)
        if (!a_used_next) {
            free(ins2->args->head->next->elem);
            ins2->args->head->next->elem = strdup(src1);
            remove_instr(instrs, start);
            return 1;
        }
    }
    
    return 0;
}

static bool reg_read_before_write_or_end(List* instrs, int start, const char* reg);
static int peephole_mov_reg_to_any(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;

    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);

    if (!dst1 || !src1 || !dst2 || !src2) return 0;
    if (!(dst1[0] == 'R' && dst1[1] >= '0' && dst1[1] <= '7' && dst1[2] == '\0')) return 0;
    if (!operands_equal(src2, dst1)) return 0;
    if (is_indirect_operand(src1) || is_indirect_operand(dst2)) return 0;

    if (!reg_read_before_write_or_end(instrs, start + 2, dst1)) {
        free(ins2->args->head->next->elem);
        ins2->args->head->next->elem = strdup(src1);
        remove_instr(instrs, start);
        return 1;
    }

    return 0;
}

/* 窥孔优化：立即数传播
 * 模式：MOV Rx, #imm; [...不修改 Rx 的指令(最多8条)...]; MOV dst, Rx
 *    → 将 MOV dst, Rx 中的 Rx 换成 #imm
 * 不删除 MOV Rx, #imm（由 peephole_dead_code / peephole_mov_reg_to_any 处理）
 * 若 Rx 之后无其他使用，后续 pass 会删除源指令。
 * 注意：只传播立即数（含 #0），不传播寄存器来源，避免错误。
 */
static int peephole_propagate_reg_imm(List* instrs, int start) {
    if (start + 2 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    if (!ins1 || is_basic_block_barrier(ins1)) return 0;
    if (!is_mov(ins1)) return 0;

    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);

    /* dst1 must be R0-R7 */
    if (!dst1 || !(dst1[0] == 'R' && dst1[1] >= '0' && dst1[1] <= '7' && dst1[2] == '\0')) return 0;
    /* src1 must be an immediate */
    if (!src1 || src1[0] != '#') return 0;

    /* Forward scan: find uses of dst1 within 8 instructions */
    int changed = 0;
    for (int offset = 1; offset <= 8 && start + offset < instrs->len; offset++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, start + offset);
        if (!ins || is_basic_block_barrier(ins)) break;

        /* Check if this instruction WRITES to dst1 (kills it) */
        if (is_mov(ins)) {
            const char* d = get_operand(ins, 0);
            if (d && operands_equal(d, dst1)) break;  /* dst1 redefined, stop */
        } else {
            /* Non-MOV: check if it writes dst1 (INC, DEC, ADD A -> dst1 etc.) */
            if (ins->op) {
                /* INC/DEC with dst1 as arg: kills dst1 */
                if ((strcmp(ins->op, "INC") == 0 || strcmp(ins->op, "DEC") == 0)) {
                    const char* a0 = get_operand(ins, 0);
                    if (a0 && operands_equal(a0, dst1)) break;
                }
                /* Any instruction with dst1 as source is OK - don't break */
                /* If it writes dst1 as a side effect, we're conservative - break */
                /* For safety: only continue through MOV, CLR C, SETB C */
                bool safe = false;
                if (strcmp(ins->op, "CLR") == 0 || strcmp(ins->op, "SETB") == 0) {
                    const char* a0 = get_operand(ins, 0);
                    if (a0 && strcmp(a0, "C") == 0) safe = true;
                }
                if (!safe) break;
            }
        }

        /* Check if this instruction READS dst1 as a source: MOV dst, Rx */
        if (is_mov(ins)) {
            const char* s = get_operand(ins, 1);
            if (s && operands_equal(s, dst1)) {
                /* Replace src with #imm */
                free(ins->args->head->next->elem);
                ins->args->head->next->elem = strdup(src1);
                changed++;
                /* Do not break: there may be more uses ahead (don't continue
                 * past the now-replaced instruction's effect on state) */
                /* Actually after replacing, dst1 is no longer read here,
                 * but it may still appear ahead. Continue scanning. */
            }
        }
    }

    return changed;
}

/* 帮助函数：检查指令是否读取 A 累加器 */
static bool instr_reads_acc(AsmInstr* ins) {
    if (!ins || !ins->op) return false;
    /* Instructions that always read A: ALU ops with A as source */
    const char* op = ins->op;
    /* MOV: reads A only if src is A (e.g. MOV Rx, A) or src is ACC.x bit (e.g. MOV C, ACC.7) */
    if (strcmp(op, "MOV") == 0) {
        const char* src = get_operand(ins, 1);
        if (src && operands_equal(src, "A")) return true;
        /* MOV C, ACC.x — bit addressing reads A */
        if (src && strncmp(src, "ACC.", 4) == 0) return true;
        return false;
    }
    /* Arithmetic/logic with A as implicit source */
    if (strcmp(op, "ADD") == 0 || strcmp(op, "ADDC") == 0 ||
        strcmp(op, "SUBB") == 0 || strcmp(op, "ANL") == 0 ||
        strcmp(op, "ORL") == 0 || strcmp(op, "XRL") == 0 ||
        strcmp(op, "CJNE") == 0 || strcmp(op, "JNZ") == 0 ||
        strcmp(op, "JZ") == 0) {
        const char* dst = get_operand(ins, 0);
        return dst && operands_equal(dst, "A");
    }
    /* Instructions that always read A */
    if (strcmp(op, "CPL") == 0 || strcmp(op, "RL") == 0 || strcmp(op, "RR") == 0 ||
        strcmp(op, "RLC") == 0 || strcmp(op, "RRC") == 0 || strcmp(op, "SWAP") == 0 ||
        strcmp(op, "DA") == 0 || strcmp(op, "INC") == 0 || strcmp(op, "DEC") == 0) {
        /* These modify A but also read it first; treat as reading A */
        const char* dst = get_operand(ins, 0);
        if (!dst) return false;
        return operands_equal(dst, "A");
    }
    /* MOVX A, @x: loads from memory INTO A (does NOT read A)
     * MOVX @x, A: stores A to memory (READS A) */
    if (strcmp(op, "MOVX") == 0) {
        const char* dst = get_operand(ins, 0);
        if (!dst) return false;
        /* MOVX @ptr, A → reads A */
        return !operands_equal(dst, "A");
    }
    /* MOVC A, @A+DPTR or @A+PC: reads A as part of address */
    if (strcmp(op, "MOVC") == 0) {
        return true; /* MOVC always uses A as index */
    }
    /* PUSH ACC / POP ACC */
    if (strcmp(op, "PUSH") == 0 || strcmp(op, "POP") == 0) {
        const char* arg = get_operand(ins, 0);
        return arg && (strcmp(arg, "ACC") == 0 || strcmp(arg, "A") == 0);
    }
    /* MUL/DIV always use A */
    if (strcmp(op, "MUL") == 0 || strcmp(op, "DIV") == 0) return true;
    return false;
}

/* 帮助函数：检查指令是否写入（覆盖）A 累加器 */
static bool instr_writes_acc(AsmInstr* ins) {
    if (!ins || !ins->op) return false;
    const char* op = ins->op;
    if (strcmp(op, "MOV") == 0 || strcmp(op, "MOVX") == 0 || strcmp(op, "MOVC") == 0) {
        const char* dst = get_operand(ins, 0);
        return dst && operands_equal(dst, "A");
    }
    /* ALU ops that write result to A */
    if (strcmp(op, "ADD") == 0 || strcmp(op, "ADDC") == 0 || strcmp(op, "SUBB") == 0 ||
        strcmp(op, "ANL") == 0 || strcmp(op, "ORL") == 0 || strcmp(op, "XRL") == 0 ||
        strcmp(op, "CPL") == 0 || strcmp(op, "RL") == 0 || strcmp(op, "RR") == 0 ||
        strcmp(op, "RLC") == 0 || strcmp(op, "RRC") == 0 || strcmp(op, "SWAP") == 0 ||
        strcmp(op, "DA") == 0) {
        const char* dst = get_operand(ins, 0);
        return dst && operands_equal(dst, "A");
    }
    if (strcmp(op, "CLR") == 0 || strcmp(op, "SETB") == 0) {
        const char* arg = get_operand(ins, 0);
        return arg && operands_equal(arg, "A");
    }
    if (strcmp(op, "MUL") == 0 || strcmp(op, "DIV") == 0) return true;
    if (strcmp(op, "POP") == 0) {
        const char* arg = get_operand(ins, 0);
        return arg && (strcmp(arg, "ACC") == 0 || strcmp(arg, "A") == 0);
    }
    /* INC/DEC A */
    if (strcmp(op, "INC") == 0 || strcmp(op, "DEC") == 0) {
        const char* dst = get_operand(ins, 0);
        return dst && operands_equal(dst, "A");
    }
    return false;
}

/* 窥孔优化：死亡 MOV A 消除
 * 如果 MOV A, src 之后，A 在被读取之前被另一条指令覆盖（写入），
 * 则此 MOV A, src 是死代码，可以删除。
 * 安全条件：src 不能是间接操作（@Rx）以避免内存读副作用
 * 向前扫描最多 6 条安全指令（非基本块边界、非分支）
 */
static int peephole_dead_mov_a(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !is_mov(ins)) return 0;
    if (is_basic_block_barrier(ins)) return 0;

    const char* dst = get_operand(ins, 0);
    const char* src = get_operand(ins, 1);
    if (!dst || !src) return 0;

    /* Must be MOV A, src */
    if (!operands_equal(dst, "A")) return 0;

    /* src must not be indirect (memory side effect) */
    if (is_indirect_operand(src)) return 0;

    /* Scan forward: if we reach a write to A before any read of A, it's dead */
    for (int offset = 1; offset <= 6 && start + offset < instrs->len; offset++) {
        AsmInstr* next = (AsmInstr*)list_get(instrs, start + offset);
        if (!next) break;
        if (is_basic_block_barrier(next)) break;

        /* If something reads A, this MOV A is live - abort */
        if (instr_reads_acc(next)) return 0;

        /* If something writes A, this MOV A is dead - remove it */
        if (instr_writes_acc(next)) {
            /* Don't remove if the write to A also reads A first (e.g. INC A, ORL A, Rx) */
            /* Those are already excluded in instr_reads_acc, but double-check combined ops */
            const char* nop = next->op;
            if (!nop) break;
            /* Pure overwrites: MOV A, src2 (not INC/DEC/ALU-with-A) */
            if (strcmp(nop, "MOV") == 0 || strcmp(nop, "MOVX") == 0 || strcmp(nop, "MOVC") == 0 ||
                strcmp(nop, "CLR") == 0 || strcmp(nop, "MUL") == 0 || strcmp(nop, "DIV") == 0 ||
                strcmp(nop, "POP") == 0) {
                remove_instr(instrs, start);
                return 1;
            }
            /* ALU ops (ADD, ANL, etc.) read A then write; A is live */
            return 0;
        }

        /* Non-A instructions: safe to skip unless they're barriers */
    }

    return 0;
}

/* --- MOV A, src; MOV mem, A → MOV mem, src（去掉 A 中转） ---
 * src 为立即数时始终安全；为寄存器/内存时需确认 A 之后不被读取 */
static int peephole_fold_mov_a_to_mem(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins1 || !ins2) return 0;
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;

    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    if (!dst1 || !src1 || !dst2 || !src2) return 0;

    /* ins1 must be: MOV A, src1 */
    if (!operands_equal(dst1, "A")) return 0;

    /* ins2 must be: MOV mem, A */
    if (!operands_equal(src2, "A")) return 0;

    /* src1 must not be A itself */
    if (operands_equal(src1, "A")) return 0;

    /* src1 must not be indirect (memory side effect) */
    if (is_indirect_operand(src1)) return 0;

    /* dst2 must be a direct memory address (not register, not indirect) */
    if (operands_equal(dst2, "A")) return 0;
    if (dst2[0] == 'R' && dst2[1] >= '0' && dst2[1] <= '7' && dst2[2] == '\0') return 0;
    if (is_indirect_operand(dst2)) return 0;

    /* Check if src1 is an immediate - always safe to fold */
    bool src_is_imm = is_immediate_operand(src1);

    /* Check if src1 is a register Rx */
    bool src_is_reg = (src1[0] == 'R' && src1[1] >= '0' && src1[1] <= '7' && src1[2] == '\0');

    /* Check if src1 is a direct memory operand (non-indirect, non-SFR-like) */
    bool src_is_mem = !src_is_imm && !src_is_reg && !is_indirect_operand(src1);

    if (!src_is_imm && !src_is_reg && !src_is_mem) return 0;

    if (src_is_reg || src_is_mem) {
        /* Must verify A is not used after MOV dst2, A before being overwritten.
         * For src_is_mem: removing MOV A,mem means A no longer has that value,
         * so any subsequent read of A (before overwrite) would see a wrong value. */
        /* Scan forward: if A is read before being written, abort */
        for (int offset = 2; offset <= 6 && start + offset < instrs->len; offset++) {
            AsmInstr* next = (AsmInstr*)list_get(instrs, start + offset);
            if (!next) break;
            if (is_basic_block_barrier(next)) break;
            if (instr_reads_acc(next)) return 0; /* A still live */
            if (instr_writes_acc(next)) break;   /* A overwritten - safe */
        }
        /* If we reach here without A being read, it's safe */
    }

    /* Perform optimization: change MOV mem, A → MOV mem, src1
     * and remove MOV A, src1 */
    free(ins2->args->head->next->elem);
    ins2->args->head->next->elem = strdup(src1);
    remove_instr(instrs, start);
    return 1;
}

/*
 * 窥孔优化：折叠 16 位寄存器加载/复制对
 *
 * 模式:
 *   MOV Ra, src1          →  MOV Rc, src1    (删除 MOV Ra, src1)
 *   MOV Rb, src2             MOV Rd, src2    (删除 MOV Rb, src2)
 *   MOV Rc, Ra
 *   MOV Rd, Rb
 *
 * 条件:
 *   - Ra, Rb, Rc, Rd 均为 R0-R7
 *   - Ra ≠ Rb, Rc ≠ Rd
 *   - Ra ≠ Rc, Rb ≠ Rd（否则第一步已经是目标）
 *   - src1, src2 不能是间接操作数（@xxx）
 *   - Ra 在 Rc 拷贝后不再被读取
 *   - Rb 在 Rd 拷贝后不再被读取
 */
static int peephole_copy_pair_fold(List* instrs, int start) {
    if (start + 3 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start + 0);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* ins3 = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* ins4 = (AsmInstr*)list_get(instrs, start + 3);
    if (!ins1 || !ins2 || !ins3 || !ins4) return 0;
    if (!is_mov(ins1) || !is_mov(ins2) || !is_mov(ins3) || !is_mov(ins4)) return 0;
    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2) ||
        is_basic_block_barrier(ins3) || is_basic_block_barrier(ins4)) return 0;

    const char* ra   = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* rb   = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    const char* rc   = get_operand(ins3, 0);
    const char* ra2  = get_operand(ins3, 1);
    const char* rd   = get_operand(ins4, 0);
    const char* rb2  = get_operand(ins4, 1);

    if (!ra || !src1 || !rb || !src2 || !rc || !ra2 || !rd || !rb2) return 0;

    /* Ra, Rb, Rc, Rd must all be R0-R7 */
    if (!is_register_operand(ra) || !is_register_operand(rb) ||
        !is_register_operand(rc) || !is_register_operand(rd)) return 0;

    /* ins3: MOV Rc, Ra  and  ins4: MOV Rd, Rb */
    if (!operands_equal(ra2, ra) || !operands_equal(rb2, rb)) return 0;

    /* Ra ≠ Rb (otherwise we'd overwrite) */
    if (operands_equal(ra, rb)) return 0;

    /* Ra ≠ Rc, Rb ≠ Rd (not already in-place) */
    if (operands_equal(ra, rc) || operands_equal(rb, rd)) return 0;

    /* src1, src2 must not be indirect */
    if (is_indirect_operand(src1) || is_indirect_operand(src2)) return 0;

    /* Rc must not be Ra or Rb (would overwrite a src we still need) */
    /* Actually: after ins3 (MOV Rc, Ra), Ra is free only if not used later.
     * But ins4 uses Rb, not Ra. So the only concern is if Rc == Rb
     * (writing Rc would overwrite the src of ins4). Prevent this. */
    if (operands_equal(rc, rb)) return 0;

    /* Check Ra is not read after position start+3 (the copy ins3 is already consuming it) */
    if (reg_read_before_write_or_end(instrs, start + 4, ra)) return 0;

    /* Check Rb is not read after position start+4 */
    if (reg_read_before_write_or_end(instrs, start + 4, rb)) return 0;

    /* Perform transformation:
     * ins3 becomes MOV Rc, src1
     * ins4 becomes MOV Rd, src2
     * ins1 and ins2 are removed */
    free(ins3->args->head->next->elem);
    ins3->args->head->next->elem = strdup(src1);
    free(ins4->args->head->next->elem);
    ins4->args->head->next->elem = strdup(src2);
    /* Remove ins2 first (higher index), then ins1 */
    remove_instr(instrs, start + 1);
    remove_instr(instrs, start);
    return 2;
}

static int peephole_drop_dead_mov_before_bit_branch(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins1 || !ins2 || !is_mov(ins1) || !ins2->op) return 0;

    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    if (!dst1 || !src1) return 0;
    if (!(dst1[0] == 'R' && dst1[1] >= '0' && dst1[1] <= '7' && dst1[2] == '\0')) return 0;
    if (!is_immediate_operand(src1)) return 0;
    if (!(strcmp(ins2->op, "JNB") == 0 || strcmp(ins2->op, "JB") == 0 || strcmp(ins2->op, "JBC") == 0)) return 0;
    if (reg_used_in_instr(ins2, dst1)) return 0;

    remove_instr(instrs, start);
    return 1;
}

static int peephole_remove_empty_local_label(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;
    if (!is_local_label(ins->op)) return 0;

    char label[64];
    if (!get_label_name(ins, label, sizeof(label))) return 0;
    if (label_is_referenced(instrs, label)) return 0;
    remove_instr(instrs, start);
    return 1;
}

/* 窥孔优化：ADD/ADDC A, #0 是算术 NOP，直接删除
 * ADD A, #0 → 无操作（不修改 A，但设置 carry；这里只删 #0 立即数的版本）
 * ADDC A, #0 → 只保留了 carry，A 值不变，删除
 * 注意：ADD A, #0 会更新 PSW（C/OV等），若之后读取 PSW flags 需保留。
 * 保守策略：若下一条指令是 ADDC（使用 carry），则不删 ADD A, #0。
 */
static int peephole_add_addc_zero(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;
    if (is_basic_block_barrier(ins)) return 0;

    bool is_add  = (strcmp(ins->op, "ADD")  == 0);
    bool is_addc = (strcmp(ins->op, "ADDC") == 0);
    if (!is_add && !is_addc) return 0;

    const char* dst = get_operand(ins, 0);
    const char* src = get_operand(ins, 1);
    if (!dst || !src) return 0;
    if (!operands_equal(dst, "A")) return 0;
    if (strcmp(src, "#0") != 0) return 0;

    /* ADD A, #0: 若下条是 ADDC，则 carry 被使用，不能删除 ADD（会清零 C） */
    if (is_add && start + 1 < instrs->len) {
        AsmInstr* next = (AsmInstr*)list_get(instrs, start + 1);
        if (next && next->op && strcmp(next->op, "ADDC") == 0) return 0;
    }

    remove_instr(instrs, start);
    return 1;
}

/* 窥孔优化：ANL A, #1; JNZ/JZ label → JB/JNB ACC.0, label
 * 测试 bit0 后立即跳转的常见模式（i & 1 检查）
 * 消除 ANL 指令和后续的条件跳转合并为一条位跳转指令
 * 前提：ANL 之后 A 值（仅 bit0 被测试）不再被读取（因为 JB/JNB 后 A 未定义）
 */
static int peephole_anl_bit0_branch(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins1 || !ins2) return 0;
    if (is_basic_block_barrier(ins1)) return 0;

    /* ins1: ANL A, #1 */
    if (!ins1->op || strcmp(ins1->op, "ANL") != 0) return 0;
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    if (!dst1 || !src1) return 0;
    if (!operands_equal(dst1, "A")) return 0;
    if (strcmp(src1, "#1") != 0) return 0;

    /* ins2: JNZ label 或 JZ label */
    if (!ins2->op) return 0;
    bool is_jnz = (strcmp(ins2->op, "JNZ") == 0);
    bool is_jz  = (strcmp(ins2->op, "JZ")  == 0);
    if (!is_jnz && !is_jz) return 0;
    if (!ins2->args || ins2->args->len < 1) return 0;
    const char* label = (const char*)list_get(ins2->args, 0);
    if (!label) return 0;

    /* 替换为 JB/JNB ACC.0, label
     * JNZ → JB ACC.0（bit0=1 则跳转）
     * JZ  → JNB ACC.0（bit0=0 则跳转）
     */
    free(ins2->op);
    ins2->op = is_jnz ? strdup("JB") : strdup("JNB");

    /* 修改参数：从 [label] 改为 [ACC.0, label] */
    /* 原来只有 1 个参数 label，需要插入 ACC.0 在前面 */
    free(ins2->args->head->elem);
    ins2->args->head->elem = strdup("ACC.0");
    list_push(ins2->args, strdup(label));

    /* 删除 ANL A, #1 */
    remove_instr(instrs, start);
    return 1;
}

/* 窥孔优化：JNZ/JZ 前的 16 位布尔化模式简化
 * 模式: ORL A, Rx; JNZ/JZ label
 * 此时 A 已经包含了低字节，ORL 使高字节也参与了零检测
 * → 这个已经是最优的16位零检测
 *
 * 但是有个常见的冗余模式来自 ne/eq 操作的结果直接用于分支：
 * pattern:
 *   MOV A, Rlo; ORL A, Rhi; JNZ/JZ label (已最优)
 *
 * 还有一个重要模式：MOV A, Rx; JNZ/JZ 之前如果 Rx 来自 ANL A, #1:
 *   ANL A, #1; MOV Rx, A; ...; MOV A, Rx; JNZ label
 * 可以优化为：MOV A, Rx(orig); JB ACC.0, label
 *
 * 更大的冗余：ne/bool 操作产生的整个 Lne_true/Lne_end 跳转链可以被替换
 * 这需要更复杂的分析，暂不实现
 */

/* Remove logical NOPs:
 *   XRL Rx, #0    (XOR with 0 = no-op)
 *   ORL Rx, #0    (OR with 0 = no-op)
 *   ANL Rx, #0FFH (AND with FFh = no-op)
 */
static int peephole_logical_nop(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;
    if (is_basic_block_barrier(ins)) return 0;

    bool is_xrl = (strcmp(ins->op, "XRL") == 0);
    bool is_orl = (strcmp(ins->op, "ORL") == 0);
    bool is_anl = (strcmp(ins->op, "ANL") == 0);
    if (!is_xrl && !is_orl && !is_anl) return 0;

    const char* src = get_operand(ins, 1);
    if (!src) return 0;

    if ((is_xrl || is_orl) && strcmp(src, "#0") == 0) {
        remove_instr(instrs, start);
        return 1;
    }
    if (is_anl && (strcmp(src, "#255") == 0 || strcmp(src, "#0FFH") == 0 || strcmp(src, "#0ffh") == 0)) {
        remove_instr(instrs, start);
        return 1;
    }
    return 0;
}

/* 窥孔优化：CLR C; RLC A → ADD A, A（逻辑左移1位）
 * CLR C; RLC A 是标准的逻辑左移，但需要2条指令。
 * ADD A, A 等效（A+A = A*2 = A<<1），只需1条指令。
 * 前提：不能在 carry 标志参与运算之前（C 不应被后面的指令读取）
 * 注意：ADD A, A 会设置 C（进位），RLC 也会设置 C，行为一致。
 */
static int peephole_clr_c_rlc_to_add(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins1 || !ins2) return 0;
    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;

    /* ins1: CLR C */
    if (!ins1->op || strcmp(ins1->op, "CLR") != 0) return 0;
    const char* clr_arg = get_operand(ins1, 0);
    if (!clr_arg || strcmp(clr_arg, "C") != 0) return 0;

    /* ins2: RLC A */
    if (!ins2->op || strcmp(ins2->op, "RLC") != 0) return 0;
    const char* rlc_arg = get_operand(ins2, 0);
    if (!rlc_arg || strcmp(rlc_arg, "A") != 0) return 0;

    /* Replace ins2: RLC A → ADD A, A */
    free(ins2->op);
    ins2->op = strdup("ADD");
    /* Change arg from ["A"] to ["A", "A"] */
    if (ins2->args->len == 1) {
        list_push(ins2->args, strdup("A"));
    }

    /* Remove ins1: CLR C */
    remove_instr(instrs, start);
    return 1;
}

/* 窥孔优化：A=#0 时 ORL A, src 等于 MOV A, src
 * 模式1: MOV A, #0; ORL A, src → MOV A, src  (删除 MOV A,#0，ORL→MOV)
 * 模式2: MOV A, #0; ORL A, src; JNZ/JZ lbl → MOV A, src; JNZ/JZ lbl
 * 适用条件: src 不是间接寻址
 */
static int peephole_orl_with_zero_acc(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins1 || !ins2) return 0;
    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;

    /* ins1 must be: MOV A, #0 */
    if (!is_mov(ins1)) return 0;
    const char* d1 = get_operand(ins1, 0);
    const char* s1 = get_operand(ins1, 1);
    if (!d1 || !s1) return 0;
    if (!operands_equal(d1, "A")) return 0;
    if (strcmp(s1, "#0") != 0) return 0;

    /* ins2 must be: ORL A, src  (src != indirect) */
    if (!ins2->op || strcmp(ins2->op, "ORL") != 0) return 0;
    const char* d2 = get_operand(ins2, 0);
    const char* s2 = get_operand(ins2, 1);
    if (!d2 || !s2) return 0;
    if (!operands_equal(d2, "A")) return 0;
    if (is_indirect_operand(s2)) return 0;

    /* Replace ORL A, src → MOV A, src; delete MOV A, #0 */
    free(ins2->op);
    ins2->op = strdup("MOV");
    remove_instr(instrs, start);
    return 1;
}

static int peephole_add_zero_16(List* instrs, int start) {
    AsmInstr *ins1, *ins2, *ins3, *ins4, *ins5, *ins6;
    const char *dst1, *src1, *dst2, *src2, *dst3, *src3;
    const char *dst4, *src4, *dst5, *src5, *dst6, *src6;

    if (start + 5 >= instrs->len) return 0;

    ins1 = (AsmInstr*)list_get(instrs, start + 0);
    ins2 = (AsmInstr*)list_get(instrs, start + 1);
    ins3 = (AsmInstr*)list_get(instrs, start + 2);
    ins4 = (AsmInstr*)list_get(instrs, start + 3);
    ins5 = (AsmInstr*)list_get(instrs, start + 4);
    ins6 = (AsmInstr*)list_get(instrs, start + 5);

    if (!is_mov(ins1) || !ins2 || !ins3 || !is_mov(ins3) || !is_mov(ins4) || !ins5 || !is_mov(ins6)) return 0;
    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2) || is_basic_block_barrier(ins3) ||
        is_basic_block_barrier(ins4) || is_basic_block_barrier(ins5) || is_basic_block_barrier(ins6)) return 0;
    if (!ins2->op || !ins5->op) return 0;
    if (strcmp(ins2->op, "ADD") != 0) return 0;
    if (strcmp(ins5->op, "ADDC") != 0) return 0;

    dst1 = get_operand(ins1, 0);
    src1 = get_operand(ins1, 1);
    dst2 = get_operand(ins2, 0);
    src2 = get_operand(ins2, 1);
    dst3 = get_operand(ins3, 0);
    src3 = get_operand(ins3, 1);
    dst4 = get_operand(ins4, 0);
    src4 = get_operand(ins4, 1);
    dst5 = get_operand(ins5, 0);
    src5 = get_operand(ins5, 1);
    dst6 = get_operand(ins6, 0);
    src6 = get_operand(ins6, 1);

    if (!operands_equal(dst1, "A") || !operands_equal(dst2, "A") || !operands_equal(src2, "#0")) return 0;
    if (!dst3 || !src1 || !operands_equal(dst3, src1) || !operands_equal(src3, "A")) return 0;
    if (!operands_equal(dst4, "A") || !operands_equal(dst5, "A") || !operands_equal(src5, "#0")) return 0;
    if (!dst6 || !src4 || !operands_equal(dst6, src4) || !operands_equal(src6, "A")) return 0;

    remove_instr(instrs, start + 5);
    remove_instr(instrs, start + 4);
    remove_instr(instrs, start + 3);
    remove_instr(instrs, start + 2);
    remove_instr(instrs, start + 1);
    remove_instr(instrs, start + 0);
    return 1;
}

/* 窥孔优化：MOV x, A; MOV A, x -> MOV x, A (删除冗余加载)
 * 也处理跨越最多2条不修改A和Rn的中间指令的情况 */
static int peephole_redundant_load(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    if (is_basic_block_barrier(ins1)) return 0;
    if (!is_mov(ins1)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);

    /* Only handle: MOV Rn, A pattern (src="A", dst=Rn) */
    if (!is_register_operand(dst1) || !operands_equal(src1, "A")) return 0;

    /* Scan forward: look for MOV A, Rn; allow instructions that don't touch A or Rn */
    for (int offset = 1; offset <= 3 && start + offset < instrs->len; offset++) {
        AsmInstr* ins_next = (AsmInstr*)list_get(instrs, start + offset);
        if (!ins_next) break;
        if (is_basic_block_barrier(ins_next)) break;

        if (is_mov(ins_next)) {
            const char* dst_n = get_operand(ins_next, 0);
            const char* src_n = get_operand(ins_next, 1);
            if (!dst_n || !src_n) break;

            /* Found MOV A, Rn: remove it */
            if (operands_equal(dst_n, "A") && operands_equal(src_n, dst1)) {
                remove_instr(instrs, start + offset);
                return 1;
            }

            /* If this MOV writes to A or dst1 (Rn), we can't skip it */
            if (operands_equal(dst_n, "A") || operands_equal(dst_n, dst1)) break;

            /* This MOV writes to some other register - safe to skip */
            continue;
        }

        /* Non-MOV instruction: check if it modifies A or dst1 */
        if (!ins_next->op) break;
        /* CLR C / SETB C are safe */
        if ((strcmp(ins_next->op, "CLR") == 0 || strcmp(ins_next->op, "SETB") == 0)) {
            const char* arg0 = get_operand(ins_next, 0);
            if (arg0 && strcmp(arg0, "C") == 0) continue;
        }
        /* Any other non-MOV instruction may modify A - stop */
        break;
    }
    
    return 0;
}

/* 窥孔优化：MOV A, x; MOV x, A -> 删除两条（如果x之后不使用） */
static int peephole_redundant_swap(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);

    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // MOV A, x; MOV x, A -> NOP (完全冗余)
    if (is_register_operand(src1) && operands_equal(dst1, "A") && operands_equal(dst2, src1) && 
        operands_equal(src2, "A")) {
        remove_instr(instrs, start + 1);
        remove_instr(instrs, start);
        return 2;
    }
    
    return 0;
}

/* 前向声明 */
static bool reg_read_before_write_or_end(List* instrs, int start, const char* reg);
static int peephole_sbuf_wait(List* instrs, int start);
static void insert_instr(List* instrs, int index, AsmInstr* ins);

/* 窥孔优化：XDATA store-then-load forward (16-bit)
 * Pattern:
 *   MOV DPTR, #addr        [0]
 *   MOV A, Rhi             [1]
 *   MOVX @DPTR, A          [2]
 *   MOV DPTR, #(addr+1)    [3]
 *   MOV A, Rlo             [4]
 *   MOVX @DPTR, A          [5]
 *   MOV DPTR, #addr        [6]  <- same addr as [0]
 *   MOVX A, @DPTR          [7]
 *   MOV Rhi2, A            [8]
 *   MOV DPTR, #(addr+1)    [9]  <- same as [3]
 *   MOVX A, @DPTR          [10]
 *   MOV Rlo2, A            [11]
 * ->
 *   MOV DPTR, #addr
 *   MOV A, Rhi
 *   MOVX @DPTR, A
 *   MOV DPTR, #(addr+1)
 *   MOV A, Rlo
 *   MOVX @DPTR, A
 *   MOV Rhi2, Rhi          (skipped if Rhi2 == Rhi)
 *   MOV Rlo2, Rlo          (skipped if Rlo2 == Rlo)
 * Saves 4 instructions (or 6 if both MOVs are no-ops)
 */
static int peephole_xdata_store_load_forward(List* instrs, int start) {
    if (start + 11 >= instrs->len) return 0;

    AsmInstr* i0  = (AsmInstr*)list_get(instrs, start);
    AsmInstr* i1  = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* i2  = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* i3  = (AsmInstr*)list_get(instrs, start + 3);
    AsmInstr* i4  = (AsmInstr*)list_get(instrs, start + 4);
    AsmInstr* i5  = (AsmInstr*)list_get(instrs, start + 5);
    AsmInstr* i6  = (AsmInstr*)list_get(instrs, start + 6);
    AsmInstr* i7  = (AsmInstr*)list_get(instrs, start + 7);
    AsmInstr* i8  = (AsmInstr*)list_get(instrs, start + 8);
    AsmInstr* i9  = (AsmInstr*)list_get(instrs, start + 9);
    AsmInstr* i10 = (AsmInstr*)list_get(instrs, start + 10);
    AsmInstr* i11 = (AsmInstr*)list_get(instrs, start + 11);

    if (!i0||!i1||!i2||!i3||!i4||!i5||!i6||!i7||!i8||!i9||!i10||!i11) return 0;

    /* Check [0]: MOV DPTR, #addr */
    if (!i0->op || strcmp(i0->op, "MOV") != 0) return 0;
    const char* dptr0 = get_operand(i0, 0);
    const char* addr0 = get_operand(i0, 1);
    if (!dptr0 || strcmp(dptr0, "DPTR") != 0) return 0;
    if (!addr0 || addr0[0] != '#') return 0;

    /* Check [1]: MOV A, Rhi */
    if (!is_mov(i1)) return 0;
    const char* a1_dst = get_operand(i1, 0);
    const char* rhi    = get_operand(i1, 1);
    if (!a1_dst || strcmp(a1_dst, "A") != 0) return 0;
    if (!rhi || rhi[0] != 'R') return 0;

    /* Check [2]: MOVX @DPTR, A */
    if (!i2->op || strcmp(i2->op, "MOVX") != 0) return 0;
    const char* movx2_dst = get_operand(i2, 0);
    if (!movx2_dst || strcmp(movx2_dst, "@DPTR") != 0) return 0;

    /* Check [3]: MOV DPTR, #(addr+1) */
    if (!is_mov(i3)) return 0;
    const char* dptr3 = get_operand(i3, 0);
    const char* addr1 = get_operand(i3, 1);
    if (!dptr3 || strcmp(dptr3, "DPTR") != 0) return 0;
    if (!addr1 || addr1[0] != '#') return 0;

    /* Check [4]: MOV A, Rlo */
    if (!is_mov(i4)) return 0;
    const char* a4_dst = get_operand(i4, 0);
    const char* rlo    = get_operand(i4, 1);
    if (!a4_dst || strcmp(a4_dst, "A") != 0) return 0;
    if (!rlo || rlo[0] != 'R') return 0;

    /* Check [5]: MOVX @DPTR, A */
    if (!i5->op || strcmp(i5->op, "MOVX") != 0) return 0;
    const char* movx5_dst = get_operand(i5, 0);
    if (!movx5_dst || strcmp(movx5_dst, "@DPTR") != 0) return 0;

    /* Check [6]: MOV DPTR, #addr  (same as [0]) */
    if (!is_mov(i6)) return 0;
    const char* dptr6 = get_operand(i6, 0);
    const char* addr6 = get_operand(i6, 1);
    if (!dptr6 || strcmp(dptr6, "DPTR") != 0) return 0;
    if (!addr6 || strcmp(addr6, addr0) != 0) return 0;  /* Must match addr0 */

    /* Check [7]: MOVX A, @DPTR */
    if (!i7->op || strcmp(i7->op, "MOVX") != 0) return 0;
    const char* a7_dst = get_operand(i7, 0);
    if (!a7_dst || strcmp(a7_dst, "A") != 0) return 0;

    /* Check [8]: MOV Rhi2, A */
    if (!is_mov(i8)) return 0;
    const char* rhi2 = get_operand(i8, 0);
    const char* a8_src = get_operand(i8, 1);
    if (!rhi2 || rhi2[0] != 'R') return 0;
    if (!a8_src || strcmp(a8_src, "A") != 0) return 0;

    /* Check [9]: MOV DPTR, #(addr+1) (same as [3]) */
    if (!is_mov(i9)) return 0;
    const char* dptr9 = get_operand(i9, 0);
    const char* addr9 = get_operand(i9, 1);
    if (!dptr9 || strcmp(dptr9, "DPTR") != 0) return 0;
    if (!addr9 || strcmp(addr9, addr1) != 0) return 0;  /* Must match addr1 */

    /* Check [10]: MOVX A, @DPTR */
    if (!i10->op || strcmp(i10->op, "MOVX") != 0) return 0;
    const char* a10_dst = get_operand(i10, 0);
    if (!a10_dst || strcmp(a10_dst, "A") != 0) return 0;

    /* Check [11]: MOV Rlo2, A */
    if (!is_mov(i11)) return 0;
    const char* rlo2   = get_operand(i11, 0);
    const char* a11_src = get_operand(i11, 1);
    if (!rlo2 || rlo2[0] != 'R') return 0;
    if (!a11_src || strcmp(a11_src, "A") != 0) return 0;

    /* All checks passed: remove [6..11] and replace with up to 2 MOVs */
    /* We need to remove 6 instructions and possibly add 0-2 MOVs */
    /* Remove from end to preserve indices: remove [11],[10],[9],[8],[7],[6] */
    remove_instr(instrs, start + 11);
    remove_instr(instrs, start + 10);
    remove_instr(instrs, start + 9);
    remove_instr(instrs, start + 8);
    remove_instr(instrs, start + 7);
    remove_instr(instrs, start + 6);

    /* Insert replacement MOVs at position start+6 */
    int insert_pos = start + 6;
    int removed_count = 6;
    int added_count = 0;

    /* MOV Rlo2, Rlo (insert first so it ends up at start+6, Rhi2 at start+7) */
    if (strcmp(rlo2, rlo) != 0) {
        AsmInstr* new_lo = calloc(1, sizeof(AsmInstr));
        new_lo->op = strdup("MOV");
        new_lo->args = make_list();
        list_push(new_lo->args, strdup(rlo2));
        list_push(new_lo->args, strdup(rlo));
        insert_instr(instrs, insert_pos, new_lo);
        added_count++;
    }

    /* MOV Rhi2, Rhi */
    if (strcmp(rhi2, rhi) != 0) {
        AsmInstr* new_hi = calloc(1, sizeof(AsmInstr));
        new_hi->op = strdup("MOV");
        new_hi->args = make_list();
        list_push(new_hi->args, strdup(rhi2));
        list_push(new_hi->args, strdup(rhi));
        insert_instr(instrs, insert_pos, new_hi);
        added_count++;
    }

    return removed_count - added_count;
}

/* 帮助函数：检查字符串是否是 "(__spill_N + 1)" 形式并与 "sym" 对应 */
static bool is_idata_hi_of(const char* hi_str, const char* lo_str) {
    /* hi_str should be "(lo_str + 1)" */
    if (!hi_str || !lo_str) return false;
    size_t lo_len = strlen(lo_str);
    /* Expected format: "(" + lo_str + " + 1)" 
     * Total length: 1 + lo_len + 5 = lo_len + 6 */
    if (strlen(hi_str) != lo_len + 6) return false;
    if (hi_str[0] != '(') return false;
    if (strncmp(hi_str + 1, lo_str, lo_len) != 0) return false;
    if (strcmp(hi_str + 1 + lo_len, " + 1)") != 0) return false;
    return true;
}

/* 窥孔优化：IDATA 16-bit store-then-load forward
 *
 * Pattern (7 instructions):
 *   [0] MOV sym, A           ; store lo
 *   [1] MOV A, hi_src        ; load hi value (reg or immediate)
 *   [2] MOV (sym + 1), A     ; store hi
 *   [3] MOV A, sym           ; reload lo  <- redundant
 *   [4] MOV Rlo, A
 *   [5] MOV A, (sym + 1)     ; reload hi  <- redundant
 *   [6] MOV Rhi, A
 *
 * We need to know what value was in A at [0].
 * Look backwards from [0] for the most recent instruction that set A:
 *   - MOV A, lo_src  -> lo_src is the value
 *   - Other (ANL, ADD etc.) -> A was computed, not easily traceable
 *     In that case, we can still forward [5-6] but not [3-4].
 *
 * Replace [3-6] with:
 *   MOV Rlo, lo_src  (if lo_src found)
 *   MOV Rhi, hi_src
 * Savings: 4 instructions (or 2 if lo_src not found)
 *
 * Also handle the simpler 8-bit case (no hi part):
 *   [0] MOV sym, A
 *   [1] MOV A, sym    <- can forward if A unchanged between [0] and [1]
 * -> remove [1]  (saves 1)
 */
static int peephole_idata_store_load_forward(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* i0 = (AsmInstr*)list_get(instrs, start);
    if (!i0 || !is_mov(i0)) return 0;
    if (is_basic_block_barrier(i0)) return 0;

    const char* dst0 = get_operand(i0, 0);
    const char* src0 = get_operand(i0, 1);

    /* [0] must be MOV sym, A  where sym is an IDATA address (memory operand, not indirect) */
    if (!dst0 || !src0) return 0;
    if (!is_memory_operand(dst0) || is_indirect_operand(dst0)) return 0;
    if (!operands_equal(src0, "A")) return 0;
    /* sym must look like a spill symbol (starts with __ or contains spill) - be permissive */
    /* Just check it's a plain IDATA symbol */

    /* Simple 8-bit case first: [0] MOV sym, A; [1] MOV A, sym */
    if (start + 1 < instrs->len) {
        AsmInstr* i1 = (AsmInstr*)list_get(instrs, start + 1);
        if (i1 && is_mov(i1) && !is_basic_block_barrier(i1)) {
            const char* dst1 = get_operand(i1, 0);
            const char* src1 = get_operand(i1, 1);
            if (operands_equal(dst1, "A") && operands_equal(src1, dst0)) {
                /* MOV sym, A; MOV A, sym -> remove MOV A, sym */
                remove_instr(instrs, start + 1);
                return 1;
            }
        }
    }

    /* 16-bit case: need at least 7 instructions total */
    if (start + 6 >= instrs->len) return 0;

    AsmInstr* i1 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* i2 = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* i3 = (AsmInstr*)list_get(instrs, start + 3);
    AsmInstr* i4 = (AsmInstr*)list_get(instrs, start + 4);
    AsmInstr* i5 = (AsmInstr*)list_get(instrs, start + 5);
    AsmInstr* i6 = (AsmInstr*)list_get(instrs, start + 6);

    if (!i1||!i2||!i3||!i4||!i5||!i6) return 0;
    if (is_basic_block_barrier(i1) || is_basic_block_barrier(i2) ||
        is_basic_block_barrier(i3) || is_basic_block_barrier(i4) ||
        is_basic_block_barrier(i5) || is_basic_block_barrier(i6)) return 0;

    /* [1]: MOV A, hi_src */
    if (!is_mov(i1)) return 0;
    const char* dst1 = get_operand(i1, 0);
    const char* hi_src = get_operand(i1, 1);
    if (!operands_equal(dst1, "A")) return 0;
    if (!hi_src) return 0;

    /* [2]: MOV (sym + 1), A */
    if (!is_mov(i2)) return 0;
    const char* dst2 = get_operand(i2, 0);
    const char* src2 = get_operand(i2, 1);
    if (!operands_equal(src2, "A")) return 0;
    if (!is_idata_hi_of(dst2, dst0)) return 0;

    /* [3]: MOV A, sym */
    if (!is_mov(i3)) return 0;
    const char* dst3 = get_operand(i3, 0);
    const char* src3 = get_operand(i3, 1);
    if (!operands_equal(dst3, "A") || !operands_equal(src3, dst0)) return 0;

    /* [4]: MOV Rlo, A */
    if (!is_mov(i4)) return 0;
    const char* rlo = get_operand(i4, 0);
    const char* src4 = get_operand(i4, 1);
    if (!rlo || rlo[0] != 'R') return 0;
    if (!operands_equal(src4, "A")) return 0;

    /* [5]: MOV A, (sym + 1) */
    if (!is_mov(i5)) return 0;
    const char* dst5 = get_operand(i5, 0);
    const char* src5 = get_operand(i5, 1);
    if (!operands_equal(dst5, "A") || !operands_equal(src5, dst2)) return 0;

    /* [6]: MOV Rhi, A */
    if (!is_mov(i6)) return 0;
    const char* rhi = get_operand(i6, 0);
    const char* src6 = get_operand(i6, 1);
    if (!rhi || rhi[0] != 'R') return 0;
    if (!operands_equal(src6, "A")) return 0;

    /* All pattern checks passed.
     * Now find what value was in A at instruction [0] by scanning backwards.
     * We look for:
     *   - MOV A, Rx  → lo_src = Rx  (only safe if contiguous or skipping non-A writes)
     *   - MOV A, #imm → lo_src = #imm
     *   - MOV Rx, A  → lo_src = Rx  (A was just stored to Rx, which equals A)
     * We only look up to 4 instructions back, skipping MOVs that don't write A.
     * Once we find any instruction that WRITES A, that is the source; stop.
     * If we find MOV Rx, A (A-save), record Rx as a candidate but keep looking
     * for the actual setter of A (unless A-save is the immediate predecessor).
     */
    const char* lo_src = NULL;
    for (int k = start - 1; k >= 0 && k >= start - 4; k--) {
        AsmInstr* prev = (AsmInstr*)list_get(instrs, k);
        if (!prev || !prev->op) break;
        if (is_label_instr(prev)) break;

        if (!is_mov(prev)) {
            /* Non-MOV: could be a computation that set A. Stop. */
            break;
        }
        const char* pdst = get_operand(prev, 0);
        const char* psrc = get_operand(prev, 1);
        if (!pdst || !psrc) break;

        if (operands_equal(pdst, "A")) {
            /* Found setter of A */
            if (is_register_operand(psrc) || is_immediate_operand(psrc)) {
                lo_src = psrc;
            }
            break;
        }
        /* MOV Rx, A at exactly start-1: A saved to Rx, Rx == A's current value */
        if (k == start - 1 && operands_equal(psrc, "A") && is_register_operand(pdst)) {
            lo_src = pdst;
            break;
        }
        /* Other MOV (not writing A): skip over it */
    }

    /* Remove [3..6] and replace with MOV Rlo, lo_src + MOV Rhi, hi_src */
    remove_instr(instrs, start + 6);
    remove_instr(instrs, start + 5);
    remove_instr(instrs, start + 4);
    remove_instr(instrs, start + 3);

    int added = 0;
    int insert_pos = start + 3;

    /* MOV Rhi, hi_src */
    if (!operands_equal(rhi, hi_src)) {
        AsmInstr* new_hi = calloc(1, sizeof(AsmInstr));
        new_hi->op = strdup("MOV");
        new_hi->args = make_list();
        list_push(new_hi->args, strdup(rhi));
        list_push(new_hi->args, strdup(hi_src));
        insert_instr(instrs, insert_pos, new_hi);
        added++;
    }

    if (lo_src) {
        /* MOV Rlo, lo_src (insert first so order is: Rlo then Rhi) */
        if (!operands_equal(rlo, lo_src)) {
            AsmInstr* new_lo = calloc(1, sizeof(AsmInstr));
            new_lo->op = strdup("MOV");
            new_lo->args = make_list();
            list_push(new_lo->args, strdup(rlo));
            list_push(new_lo->args, strdup(lo_src));
            insert_instr(instrs, insert_pos, new_lo);
            added++;
        }
    } else {
        /* Can't trace lo_src: keep the original [3-4] pair but forward hi */
        /* Restore MOV A, sym; MOV Rlo, A */
        AsmInstr* new_lo_dst = calloc(1, sizeof(AsmInstr));
        new_lo_dst->op = strdup("MOV");
        new_lo_dst->args = make_list();
        list_push(new_lo_dst->args, strdup(rlo));
        list_push(new_lo_dst->args, strdup(dst0)); /* MOV Rlo, sym (direct) */
        insert_instr(instrs, insert_pos, new_lo_dst);
        added++;
    }

    /* Net savings: removed 4, added <= 2 → net >= 2 */
    return 4 - added;
}

/* 窥孔优化：IDATA 直接加载前向替换
 * 如果有: MOV Rx, sym (直接 IDATA 加载)
 * 且向前查找能找到: MOV sym, A (存储), 且之前找到 MOV Rsave, A (保存 A 到寄存器)
 * 且 Rsave 在 sym 存储和当前加载之间未被修改
 * 则: MOV Rx, sym -> MOV Rx, Rsave (避免内存访问)
 *
 * Pattern:
 *   MOV Rsave, A   <- backward scan finds this
 *   ... (no modification of Rsave or sym)
 *   MOV sym, A     <- backward scan finds this first
 *   ... (no modification of sym)
 *   MOV Rx, sym    <- current instruction (start)
 */
static int peephole_idata_load_from_reg(List* instrs, int start) {
    if (start < 1) return 0;

    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !is_mov(ins)) return 0;
    if (is_basic_block_barrier(ins)) return 0;

    const char* dst = get_operand(ins, 0);
    const char* sym = get_operand(ins, 1);

    /* Target must be a register, source must be direct IDATA (not indirect, not register, not imm) */
    if (!dst || !sym) return 0;
    if (!is_register_operand(dst) || operands_equal(dst, "A")) return 0;
    if (is_register_operand(sym) || is_immediate_operand(sym) || is_indirect_operand(sym)) return 0;

    /* Look backward for MOV sym, A (the store instruction) */
    const char* reg_save = NULL;
    bool found_store = false;
    for (int k = start - 1; k >= 0 && k >= start - 8; k--) {
        AsmInstr* prev = (AsmInstr*)list_get(instrs, k);
        if (!prev || !prev->op) break;
        if (is_label_instr(prev)) break; /* basic block boundary */
        if (is_control_transfer_instr(prev)) break;

        if (is_mov(prev)) {
            const char* pdst = get_operand(prev, 0);
            const char* psrc = get_operand(prev, 1);
            if (!pdst || !psrc) break;

            if (!found_store) {
                /* Looking for MOV sym, A */
                if (operands_equal(pdst, sym) && operands_equal(psrc, "A")) {
                    found_store = true;
                    /* Now look further back for MOV Rsave, A */
                    for (int j = k - 1; j >= 0 && j >= k - 4; j--) {
                        AsmInstr* pprev = (AsmInstr*)list_get(instrs, j);
                        if (!pprev || !pprev->op) break;
                        if (is_label_instr(pprev)) break;
                        if (!is_mov(pprev)) {
                            /* Non-MOV: might have computed A. Stop. */
                            break;
                        }
                        const char* ppdst = get_operand(pprev, 0);
                        const char* ppsrc = get_operand(pprev, 1);
                        if (!ppdst || !ppsrc) break;
                        if (operands_equal(ppdst, "A")) break; /* A was set here - wrong direction */
                        if (operands_equal(ppsrc, "A") && is_register_operand(ppdst)) {
                            /* Found MOV Rsave, A: check Rsave not modified between j and start */
                            bool modified = false;
                            for (int m = j + 1; m < start; m++) {
                                AsmInstr* mid = (AsmInstr*)list_get(instrs, m);
                                if (!mid || !mid->op) break;
                                if (is_basic_block_barrier(mid)) { modified = true; break; }
                                if (is_mov(mid)) {
                                    const char* mdst = get_operand(mid, 0);
                                    if (operands_equal(mdst, ppdst)) { modified = true; break; }
                                }
                            }
                            if (!modified) {
                                reg_save = ppdst;
                            }
                        }
                        /* If MOV writes to sym, stop */
                        if (operands_equal(ppdst, sym)) break;
                    }
                    break; /* Stop backward scan once store is found */
                }
                /* If something writes to sym between start and the store, stop */
                if (operands_equal(pdst, sym)) break;
                /* If instruction is a barrier or writes to A from memory, continue */
            }
        } else {
            /* Non-MOV: check if it's a barrier */
            if (is_control_transfer_instr(prev)) break;
            /* Other non-MOV: might write to sym or A, stop conservatively */
            break;
        }
    }

    if (!found_store || !reg_save) return 0;

    /* Replace MOV Rx, sym with MOV Rx, reg_save */
    free(ins->args->head->next->elem);
    ins->args->head->next->elem = strdup(reg_save);
    return 1;
}

/* 通用 spill 16-bit store-reload forward 优化
 *
 * 处理两种形式的 store：
 *  A 形式: MOV sym, A;        MOV (sym+1), #imm
 *  B 形式: MOV sym, Rx;       MOV (sym+1), Ry
 *
 * 然后跨越至多 MAX_SCAN 条不涉及 sym 的指令，找到对应 reload：
 *  MOV Rlo, sym;  MOV Rhi, (sym+1)
 *
 * 替换 reload 为：MOV Rlo, lo_src; MOV Rhi, hi_src
 * （去掉内存访问，节省 2 条指令；若 Rlo==lo_src 或 Rhi==hi_src 则各省 1 条）
 *
 * 安全条件：
 *  - sym 和 (sym+1) 在 store 和 reload 之间未被写入
 *  - lo_src/hi_src（寄存器）在 store 和 reload 之间未被写入
 *    对于立即数，无需检查
 *  - 中间没有基本块边界（标签/跳转）
 */
static int peephole_spill16_store_reload_forward(List* instrs, int start) {
    #define MAX_SCAN 16
    if (start + 3 >= instrs->len) return 0;

    AsmInstr* s0 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* s1 = (AsmInstr*)list_get(instrs, start + 1);
    if (!s0 || !s1) return 0;
    if (!is_mov(s0) || !is_mov(s1)) return 0;
    if (is_basic_block_barrier(s0) || is_basic_block_barrier(s1)) return 0;

    const char* sym    = get_operand(s0, 0);
    const char* lo_src = get_operand(s0, 1);
    const char* hi_dst = get_operand(s1, 0);
    const char* hi_src = get_operand(s1, 1);

    if (!sym || !lo_src || !hi_dst || !hi_src) return 0;

    /* sym 必须是直接 IDATA 符号（非寄存器、非立即数、非间接） */
    if (is_register_operand(sym) || is_immediate_operand(sym) || is_indirect_operand(sym)) return 0;

    /* hi_dst 必须是 (sym + 1) */
    if (!is_idata_hi_of(hi_dst, sym)) return 0;

    /* lo_src: A 或 寄存器 Rx；hi_src: 立即数 或 寄存器 */
    bool lo_is_A   = operands_equal(lo_src, "A");
    bool lo_is_reg = (!lo_is_A) && is_register_operand(lo_src);
    if (!lo_is_A && !lo_is_reg) return 0;  /* 不处理从内存 store 到 spill 的情况 */
    bool hi_is_imm = is_immediate_operand(hi_src);
    bool hi_is_reg = !hi_is_imm && is_register_operand(hi_src);
    if (!hi_is_imm && !hi_is_reg) return 0;

    /* 如果 lo 是 A，需要向前追踪 A 的来源
     * 仅接受：A 来自 MOV A, Rx（Rx 在 start-1 之前）
     * 或在 start 的前一条指令中有 MOV Rsave, A（A 保存到寄存器）*/
    const char* lo_forwarded = NULL;  /* 如果 lo_src=A，这里存实际来源 */
    if (lo_is_A) {
        /* 向后扫描找 A 的设置指令（或 A 的保存指令） */
        for (int k = start - 1; k >= 0 && k >= start - 6; k--) {
            AsmInstr* prev = (AsmInstr*)list_get(instrs, k);
            if (!prev || !prev->op) break;
            if (is_label_instr(prev) || is_control_transfer_instr(prev)) break;
            if (!is_mov(prev)) {
                /* 非 MOV（ALU 指令等）设置了 A，停止 */
                break;
            }
            const char* pdst = get_operand(prev, 0);
            const char* psrc = get_operand(prev, 1);
            if (!pdst || !psrc) break;
            if (operands_equal(pdst, "A")) {
                /* 找到 A 的设置：MOV A, Rx */
                if (is_register_operand(psrc)) {
                    lo_forwarded = psrc;
                }
                break;
            }
            /* MOV Rsave, A：A 的当前值保存到 Rsave */
            if (operands_equal(psrc, "A") && is_register_operand(pdst)) {
                /* 只有当这是直接前驱时才用（否则 A 可能已变） */
                if (k == start - 1) {
                    lo_forwarded = pdst;
                    break;
                }
            }
        }
        /* 如果找不到 A 的来源寄存器，不能前向传播 lo */
        /* 但 hi 仍然可以前向传播（如果 hi_is_imm） */
    } else {
        lo_forwarded = lo_src;  /* lo_src 本身是寄存器 */
    }

    /* 现在向前扫描，查找 MOV Rlo, sym; MOV Rhi, (sym+1) */
    int reload_lo_idx = -1;
    int reload_hi_idx = -1;

    for (int j = start + 2; j < instrs->len && j < start + 2 + MAX_SCAN; j++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, j);
        if (!ins || !ins->op) break;

        /* 基本块边界：停止 */
        if (is_label_instr(ins)) break;
        if (is_control_transfer_instr(ins)) break;

        if (!is_mov(ins)) {
            /* 非 MOV 指令：检查是否是安全的 ALU 指令（不写 sym）
             * 保守：非 MOV 不涉及 IDATA，继续扫描 */
            continue;
        }

        const char* idst = get_operand(ins, 0);
        const char* isrc = get_operand(ins, 1);
        if (!idst || !isrc) continue;

        /* 如果发现向 sym 写入，停止 */
        if (operands_equal(idst, sym) || operands_equal(idst, hi_dst)) break;

        /* 检查 reload lo: MOV Rlo, sym */
        if (operands_equal(isrc, sym) && is_register_operand(idst)) {
            reload_lo_idx = j;
            continue;
        }
        /* 检查 reload hi: MOV Rhi, (sym+1) */
        if (operands_equal(isrc, hi_dst) && is_register_operand(idst)) {
            reload_hi_idx = j;
            continue;
        }
    }

    if (reload_lo_idx < 0 && reload_hi_idx < 0) return 0;

    int saved = 0;

    /* 替换 reload_hi（先处理较大的索引以免影响 reload_lo 的索引） */
    if (reload_hi_idx >= 0) {
        /* 确认 hi_src 在 start+2 到 reload_hi_idx 之间没有被 sym 的 store 覆盖 */
        bool hi_safe = true;
        for (int k = start + 2; k < reload_hi_idx && hi_safe; k++) {
            AsmInstr* ins = (AsmInstr*)list_get(instrs, k);
            if (!ins || !ins->op) break;
            if (is_mov(ins)) {
                const char* d = get_operand(ins, 0);
                /* 如果发现有对 (sym+1) 的再次写入，不安全 */
                if (operands_equal(d, hi_dst)) { hi_safe = false; break; }
                /* 如果 hi_src 是寄存器，检查是否被覆盖 */
                if (hi_is_reg && operands_equal(d, hi_src)) { hi_safe = false; break; }
            }
        }
        if (hi_safe) {
            AsmInstr* rhi_ins = (AsmInstr*)list_get(instrs, reload_hi_idx);
            const char* rhi = get_operand(rhi_ins, 0);
            if (operands_equal(rhi, hi_src)) {
                /* rhi == hi_src，整条指令是自赋值，删除 */
                remove_instr(instrs, reload_hi_idx);
                saved++;
                if (reload_lo_idx > reload_hi_idx) reload_lo_idx--;
            } else {
                /* 替换 source 操作数为 hi_src（直接使用立即数或寄存器）*/
                free(rhi_ins->args->head->next->elem);
                rhi_ins->args->head->next->elem = strdup(hi_src);
                saved++;
            }
        }
    }

    if (reload_lo_idx >= 0 && lo_forwarded) {
        /* 验证 lo_forwarded 在 store 和 reload_lo 之间未被修改 */
        bool lo_safe = true;
        if (is_register_operand(lo_forwarded)) {
            for (int k = start + 2; k < reload_lo_idx && lo_safe; k++) {
                AsmInstr* ins = (AsmInstr*)list_get(instrs, k);
                if (!ins || !ins->op) break;
                if (is_mov(ins)) {
                    const char* d = get_operand(ins, 0);
                    if (operands_equal(d, lo_forwarded)) { lo_safe = false; break; }
                    /* sym 本身被覆盖 */
                    if (operands_equal(d, sym)) { lo_safe = false; break; }
                }
            }
        }
        if (lo_safe) {
            AsmInstr* rlo_ins = (AsmInstr*)list_get(instrs, reload_lo_idx);
            const char* rlo = get_operand(rlo_ins, 0);
            if (operands_equal(rlo, lo_forwarded)) {
                remove_instr(instrs, reload_lo_idx);
                saved++;
            } else {
                free(rlo_ins->args->head->next->elem);
                rlo_ins->args->head->next->elem = strdup(lo_forwarded);
                saved++;
            }
        }
    }

    return saved;
    #undef MAX_SCAN
}

/* 检查指令是否不修改指定寄存器 */
static bool instr_does_not_modify_reg(AsmInstr* ins, const char* reg) {
    if (!ins || !reg) return true;
    
    // CLR C, SETB C 等不修改寄存器
    if (ins->op && (strcmp(ins->op, "CLR") == 0 || strcmp(ins->op, "SETB") == 0)) {
        return true;
    }
    
    // 检查目标操作数是否是该寄存器
    if (is_mov(ins)) {
        const char* dst = get_operand(ins, 0);
        return !operands_equal(dst, reg);
    }

    return true;
}

/* 窥孔优化：MOV Rx, src; [CLR C]; MOV A, Rx -> [CLR C]; MOV A, src (如果 Rx 之后不再使用) */
static int peephole_eliminate_temp_reg(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    if (is_basic_block_barrier(ins1)) return 0;
    if (!is_mov(ins1)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    
    // 第一条必须是 MOV Rx, src
    if (!dst1 || dst1[0] != 'R' || operands_equal(src1, "A")) {
        return 0;
    }

    /* 如果 src1 是间接寻址（@R0/@R1），则不安全 */
    if (is_indirect_operand(src1)) return 0;

    /* src1 是内存操作数（如变量、spill槽、SFR）时，需要额外验证：
     * 中间的指令不能写入 src1（内存被修改） */
    bool src1_is_mem = is_memory_operand(src1);
    
    /* 查找下一条 MOV A, Rx 指令
     * 可以跨越不影响 Rx 或 A 的指令（MOV, CLR C, SETB C）
     * 最多扫描 6 条 */
    int offset = 1;
    while (start + offset < instrs->len && offset <= 6) {
        AsmInstr* ins_next = (AsmInstr*)list_get(instrs, start + offset);
        if (!ins_next) break;
        if (is_basic_block_barrier(ins_next)) break;
        
        if (is_mov(ins_next)) {
            const char* dst_next = get_operand(ins_next, 0);
            const char* src_next = get_operand(ins_next, 1);
            if (!dst_next || !src_next) break;
            
            /* Found MOV A, Rx: apply optimization */
            if (operands_equal(dst_next, "A") && operands_equal(src_next, dst1)) {
                /* Check Rx is not used after this point */
                if (!reg_read_before_write_or_end(instrs, start + offset + 1, dst1)) {
                    free(ins_next->args->head->next->elem);
                    ins_next->args->head->next->elem = strdup(src1);
                    remove_instr(instrs, start);
                    return 1;
                }
                break; /* Rx is used later, can't eliminate */
            }
            
            /* If this MOV writes to A or dst1 (Rx), stop */
            if (operands_equal(dst_next, "A") || operands_equal(dst_next, dst1)) break;

            /* If src1 is a memory location, check if this MOV writes to it */
            if (src1_is_mem && operands_equal(dst_next, src1)) break;

            /* This MOV writes to some other register - safe to skip */
            offset++;
            continue;
        }
        
        /* CLR C / SETB C are safe */
        if (ins_next->op && (strcmp(ins_next->op, "CLR") == 0 || strcmp(ins_next->op, "SETB") == 0)) {
            const char* arg0 = get_operand(ins_next, 0);
            if (arg0 && strcmp(arg0, "C") == 0) { offset++; continue; }
        }
        
        /* Any other non-MOV instruction may modify A or Rx - stop */
        break;
    }
    
    return 0;
}

/*
 * 窥孔优化：复制传播
 * 模式：MOV Ra, src; [跳过不影响Ra/src的指令]; MOV Rb, Ra
 * 条件：Ra≠A, Rb≠A, Ra≠Rb, src非间接, Ra之后不被使用
 * 动作：MOV Rb, Ra → MOV Rb, src，删除 MOV Ra, src
 * 例：MOV R0, R4; MOV R1, R2; MOV R6, R0 → MOV R1, R2; MOV R6, R4
 */
static int peephole_copy_propagate(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    if (!ins1 || !is_mov(ins1) || is_basic_block_barrier(ins1)) return 0;

    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    if (!dst1 || !src1) return 0;

    /* dst1 must be Rx (not A, not memory, not indirect) */
    if (!is_register_operand(dst1) || operands_equal(dst1, "A")) return 0;

    /* src1 must not be indirect */
    if (is_indirect_operand(src1)) return 0;
    /* src1 must not be A (we don't track A liveness here) */
    if (operands_equal(src1, "A")) return 0;

    bool src1_is_mem = is_memory_operand(src1);

    /* Scan forward for MOV Rb, Ra (where Rb is any Rx, Rb != Ra) */
    int offset = 1;
    while (start + offset < instrs->len && offset <= 6) {
        AsmInstr* ins_next = (AsmInstr*)list_get(instrs, start + offset);
        if (!ins_next) break;
        if (is_basic_block_barrier(ins_next)) break;

        if (is_mov(ins_next)) {
            const char* dst_next = get_operand(ins_next, 0);
            const char* src_next = get_operand(ins_next, 1);
            if (!dst_next || !src_next) break;

            /* Found MOV Rb, Ra */
            if (is_register_operand(dst_next) && !operands_equal(dst_next, "A") &&
                operands_equal(src_next, dst1) && !operands_equal(dst_next, dst1)) {
                /* Check Ra is not used after this point */
                if (!reg_read_before_write_or_end(instrs, start + offset + 1, dst1)) {
                    /* Replace MOV Rb, Ra → MOV Rb, src1 */
                    free(ins_next->args->head->next->elem);
                    ins_next->args->head->next->elem = strdup(src1);
                    remove_instr(instrs, start);
                    return 1;
                }
                break; /* Ra is used later */
            }

            /* Stop if dst_next == Ra (Ra overwritten) */
            if (operands_equal(dst_next, dst1)) break;
            /* Stop if src1 is memory and dst_next == src1 (memory overwritten) */
            if (src1_is_mem && operands_equal(dst_next, src1)) break;
            /* Skip this MOV (unrelated) */
            offset++;
            continue;
        }

        /* CLR C / SETB C are safe to skip */
        if (ins_next->op && (strcmp(ins_next->op, "CLR") == 0 || strcmp(ins_next->op, "SETB") == 0)) {
            const char* arg0 = get_operand(ins_next, 0);
            if (arg0 && strcmp(arg0, "C") == 0) { offset++; continue; }
        }

        /* Any other non-MOV instruction may use Ra or src1 - stop */
        break;
    }

    return 0;
}

/* 窥孔优化：前向目标替换
 * 模式：MOV Rd, A; [中间指令(最多8条)]; MOV Rf, Rd
 *    → MOV Rf, A; [中间指令]; (删除 MOV Rf, Rd)
 * 条件：
 *   - ins1: MOV Rd, A (dst=R0-R7, src=A)
 *   - 中间指令可以自由修改 A（这正是 Rd 被需要的原因）
 *   - 中间指令不能读取 Rd（除了 terminal MOV Rf, Rd）
 *   - 中间指令不能写入 Rf
 *   - 扫描窗口内 Rd 只被用于一次 terminal copy
 *   - Rf != Rd, Rf 是 R0-R7（不是 A，不是内存）
 * 典型场景：16位算术写入临时寄存器再复制到目标
 *   ADD A, R5; MOV R1, A; MOV A, R6; ADDC A, R4; MOV R0, A; MOV R7, R1; MOV R6, R0
 *   → ADD A, R5; MOV R7, A; MOV A, R6; ADDC A, R4; MOV R6, A
 */
static int peephole_forward_copy_to_dest(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    if (!ins1 || !is_mov(ins1) || is_basic_block_barrier(ins1)) return 0;

    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    if (!dst1 || !src1) return 0;

    /* dst1 must be R0-R7 */
    if (!(dst1[0] == 'R' && dst1[1] >= '0' && dst1[1] <= '7' && dst1[2] == '\0')) return 0;
    /* src1 must be A */
    if (!operands_equal(src1, "A")) return 0;

    /* 向前扫描，查找唯一用途：MOV Rf, Rd */
    for (int offset = 1; offset <= 8 && start + offset < instrs->len; offset++) {
        AsmInstr* ins_next = (AsmInstr*)list_get(instrs, start + offset);
        if (!ins_next || is_basic_block_barrier(ins_next)) break;

        if (is_mov(ins_next)) {
            const char* dst_n = get_operand(ins_next, 0);
            const char* src_n = get_operand(ins_next, 1);
            if (!dst_n || !src_n) break;

            /* 发现 MOV Rf, Rd (terminal copy) */
            if (operands_equal(src_n, dst1)) {
                /* Rf 必须是 R0-R7（不是 A，不是内存） */
                if (!(dst_n[0] == 'R' && dst_n[1] >= '0' && dst_n[1] <= '7' && dst_n[2] == '\0')) break;
                /* Rf != Rd */
                if (operands_equal(dst_n, dst1)) break;
                /* 验证：Rd 在 terminal copy 之后未被读取 */
                if (reg_read_before_write_or_end(instrs, start + offset + 1, dst1)) break;
                /* 执行替换：将 ins1 的 dst 改为 Rf，删除 terminal copy */
                free(ins1->args->head->elem);
                ins1->args->head->elem = strdup(dst_n);
                remove_instr(instrs, start + offset);
                return 1;
            }

            /* 如果中间指令写入 Rd，则 Rd 被重定义，终止扫描 */
            if (operands_equal(dst_n, dst1)) break;
            /* 如果中间指令写入 Rf（我们想用的目标），也需要停止
             * 注意：此时我们还不知道 Rf，但可以保守地检查当前写入目标
             * 是否与后面任何可能的 Rf 冲突 — 但由于我们还不知道 Rf，
             * 只有在找到 terminal copy 时才做检查，这里仅检查 Rd */
            /* 中间 MOV 可以安全跳过（不涉及 Rd） */
            continue;
        }

        /* 非 MOV 指令：检查是否读取 Rd（作为操作数） */
        if (ins_next->op) {
            /* 检查 Rd 是否作为源操作数出现 */
            bool rd_used = false;
            ListNode* node = ins_next->args ? ins_next->args->head : NULL;
            while (node) {
                const char* arg = (const char*)node->elem;
                if (arg && operands_equal(arg, dst1)) { rd_used = true; break; }
                node = node->next;
            }
            if (rd_used) break; /* Rd 被非 MOV 指令使用，无法前向传播 */
            /* 非 MOV 指令可自由修改 A，这是预期的 */
        }
    }

    return 0;
}

/* 从 start 向后扫描，判断 reg 是否在被覆盖前被读取。
 * 遇到 RET：R6/R7 视为活跃（返回值寄存器）。
 * 遇到 label/分支：保守返回 true。 */
static bool reg_read_before_write_or_end(List* instrs, int start, const char* reg) {
    if (!reg || !instrs) return false;
    
    for (int i = start; i < instrs->len; i++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, i);
        if (!ins) continue;

        if (ins->op && strcmp(ins->op, "RET") == 0)
            return operands_equal(reg, "R7") || operands_equal(reg, "R6");

        if (is_basic_block_barrier(ins)) return true;
        
        if (is_mov(ins)) {
            const char* dst = get_operand(ins, 0);
            if (is_indirect_operand(dst) && operand_reads_reg(dst, reg)) return true;
            if (operands_equal(dst, reg)) return false;
        }
        
        if (ins->args) {
            int start_arg = is_mov(ins) ? 1 : 0;
            for (int j = start_arg; j < ins->args->len; j++) {
                const char* arg = (const char*)list_get(ins->args, j);
                if (operand_reads_reg(arg, reg)) return true;
            }
        }
    }
    return false;
}

/* 窥孔优化：DEC/DJNZ 生成
 *
 * 模式 A1（相同寄存器，生成 DJNZ，节省 3 条）：
 *   MOV A, Rx        [0]
 *   DEC A            [1]
 *   MOV Rx, A        [2]  (写回同一寄存器)
 *   JNZ label        [3]
 * →  DJNZ Rx, label
 *
 * 模式 A2（不同寄存器，生成 MOV+DJNZ，节省 2 条）：
 *   MOV A, Rx        [0]
 *   DEC A            [1]
 *   MOV Ry, A        [2]  (Ry ≠ Rx)
 *   JNZ label        [3]
 * →  MOV Ry, Rx
 *    DJNZ Ry, label
 *
 * 模式 B1（相同寄存器，生成 DEC+JZ，节省 2 条）：
 *   MOV A, Rx        [0]
 *   DEC A            [1]
 *   MOV Rx, A        [2]
 *   JZ  label        [3]
 * →  DEC Rx
 *    JZ  label
 *
 * 模式 B2（不同寄存器，生成 MOV+DEC+JZ，节省 1 条）：
 *   MOV A, Rx        [0]
 *   DEC A            [1]
 *   MOV Ry, A        [2]  (Ry ≠ Rx)
 *   JZ  label        [3]
 * →  MOV Ry, Rx
 *    DEC Ry
 *    JZ  label
 *
 * 条件：
 *   - [0]~[3] 均不是基本块边界
 *   - [0] 的源 Rx 是 R0-R7（不是 A）
 *   - [2] 的目标 Ry 是 R0-R7（不是 A）
 *   - 对于 A2：A 在 [3] 之后不再被读取（保证 "MOV Ry,Rx" 时 A 丢失不影响后续）
 * 注：DJNZ Rx,label = DEC Rx; JNZ label（减后非零则跳）
 */
static int peephole_dec_reg_branch(List* instrs, int start) {
    if (start + 3 >= instrs->len) return 0;

    AsmInstr* i0 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* i1 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* i2 = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* i3 = (AsmInstr*)list_get(instrs, start + 3);
    if (!i0 || !i1 || !i2 || !i3) return 0;
    /* [0],[1],[2] 不能是基本块边界；[3] 本身是跳转（控制转移），允许但不能是标签 */
    if (is_basic_block_barrier(i0) || is_basic_block_barrier(i1) ||
        is_basic_block_barrier(i2)) return 0;
    if (is_label_instr(i3)) return 0;

    /* [0]: MOV A, Rx  (Rx = R0-R7) */
    if (!is_mov(i0)) return 0;
    const char* dst0 = get_operand(i0, 0);
    const char* src0 = get_operand(i0, 1);
    if (!dst0 || !src0) return 0;
    if (!operands_equal(dst0, "A")) return 0;
    if (!(src0[0] == 'R' && src0[1] >= '0' && src0[1] <= '7' && src0[2] == '\0')) return 0;

    /* [1]: DEC A */
    if (!i1->op || strcmp(i1->op, "DEC") != 0) return 0;
    const char* dec_arg = get_operand(i1, 0);
    if (!dec_arg || !operands_equal(dec_arg, "A")) return 0;

    /* [2]: MOV Ry, A  (Ry = R0-R7) */
    if (!is_mov(i2)) return 0;
    const char* dst2 = get_operand(i2, 0);
    const char* src2 = get_operand(i2, 1);
    if (!dst2 || !src2) return 0;
    if (!(dst2[0] == 'R' && dst2[1] >= '0' && dst2[1] <= '7' && dst2[2] == '\0')) return 0;
    if (!operands_equal(src2, "A")) return 0;

    /* 先尝试 5步模式：[3] 是另一个 MOV Rz, A，[4] 才是 JZ/JNZ
     * 例：MOV A, R0; DEC A; MOV R1, A; MOV R0, A; JZ label
     * 只处理 Rz == Rx 的情况（写回原寄存器）
     */
    if (start + 4 < instrs->len) {
        AsmInstr* i3_extra = (AsmInstr*)list_get(instrs, start + 3);
        AsmInstr* i4_jump  = (AsmInstr*)list_get(instrs, start + 4);
        if (i3_extra && i4_jump &&
            !is_basic_block_barrier(i3_extra) && !is_label_instr(i4_jump) &&
            is_mov(i3_extra)) {
            const char* dst3e = get_operand(i3_extra, 0);
            const char* src3e = get_operand(i3_extra, 1);
            if (dst3e && src3e && operands_equal(src3e, "A") &&
                operands_equal(dst3e, src0) && /* Rz == Rx: 写回同一寄存器 */
                i4_jump->op) {
                bool jnz5 = (strcmp(i4_jump->op, "JNZ") == 0);
                bool jz5  = (strcmp(i4_jump->op, "JZ")  == 0);
                if ((jnz5 || jz5) && i4_jump->args && i4_jump->args->len >= 1) {
                    const char* label5 = (const char*)list_get(i4_jump->args, 0);
                    if (label5) {
                        /* 5步模式匹配成功:
                         * MOV A, Rx; DEC A; MOV Ry, A; MOV Rx, A; JNZ/JZ label
                         * 转换为:
                         * MOV Ry, Rx (节省 2 条)
                         * DEC Rx
                         * JNZ/JZ label (JNZ → DJNZ Rx)
                         */
                        if (jnz5) {
                            /* → MOV Ry, Rx; DJNZ Rx, label (2条，节省3) */
                            /* 修改 i4_jump: JNZ → DJNZ Rx, label */
                            free(i4_jump->op);
                            i4_jump->op = strdup("DJNZ");
                            free(i4_jump->args->head->elem);
                            i4_jump->args->head->elem = strdup(src0);
                            list_push(i4_jump->args, strdup(label5));
                            /* 修改 i3_extra: MOV Rx, A → DEC Rx（用来做 DJNZ 的 dec）
                             * 实际上 DJNZ 自身就有 dec，不需要单独 DEC；
                             * 只需 MOV Ry, Rx; DJNZ Rx, label */
                            /* i2: MOV Ry, A → MOV Ry, Rx */
                            free(i2->args->head->next->elem);
                            i2->args->head->next->elem = strdup(src0);
                            /* 删除 [0] MOV A,Rx; [1] DEC A; [3] MOV Rx,A（高到低） */
                            remove_instr(instrs, start + 3); /* i3_extra */
                            remove_instr(instrs, start + 1); /* i1 DEC A */
                            remove_instr(instrs, start + 0); /* i0 MOV A,Rx */
                            return 3;
                        } else {
                            /* → MOV Ry, Rx; DEC Rx; JZ label (3条，节省2) */
                            /* i2: MOV Ry, A → MOV Ry, Rx */
                            free(i2->args->head->next->elem);
                            i2->args->head->next->elem = strdup(src0);
                            /* i3_extra: MOV Rx, A → DEC Rx */
                            free(i3_extra->op);
                            i3_extra->op = strdup("DEC");
                            if (i3_extra->args->len >= 2) {
                                ListNode* second = i3_extra->args->head->next;
                                if (second) {
                                    free(second->elem);
                                    i3_extra->args->head->next = second->next;
                                    if (second->next) second->next->prev = i3_extra->args->head;
                                    else i3_extra->args->tail = i3_extra->args->head;
                                    free(second);
                                    i3_extra->args->len--;
                                }
                            }
                            /* 删除 [0] MOV A,Rx; [1] DEC A */
                            remove_instr(instrs, start + 1);
                            remove_instr(instrs, start + 0);
                            return 2;
                        }
                    }
                }
            }
        }
    }

    bool same_reg = operands_equal(dst2, src0); /* Ry == Rx */

    /* [3]: JNZ label  or  JZ label */
    if (!i3->op) return 0;
    bool is_jnz = (strcmp(i3->op, "JNZ") == 0);
    bool is_jz  = (strcmp(i3->op, "JZ")  == 0);
    if (!is_jnz && !is_jz) return 0;
    if (!i3->args || i3->args->len < 1) return 0;
    const char* label = (const char*)list_get(i3->args, 0);
    if (!label) return 0;

    if (is_jnz) {
        if (same_reg) {
            /* 模式 A1: 生成 DJNZ Rx, label (替换 4 条为 1 条，节省 3) */
            free(i3->op);
            i3->op = strdup("DJNZ");
            /* 参数从 [label] 改为 [Rx, label] */
            free(i3->args->head->elem);
            i3->args->head->elem = strdup(src0);   /* Rx */
            list_push(i3->args, strdup(label));     /* label */
            /* 删除 [0],[1],[2]（从高到低） */
            remove_instr(instrs, start + 2);
            remove_instr(instrs, start + 1);
            remove_instr(instrs, start + 0);
            return 3;
        } else {
            /* 模式 A2: 生成 MOV Ry, Rx; DJNZ Ry, label (替换 4 条为 2 条，节省 2) */
            /* 修改 i3: JNZ label → DJNZ Ry, label */
            free(i3->op);
            i3->op = strdup("DJNZ");
            free(i3->args->head->elem);
            i3->args->head->elem = strdup(dst2);   /* Ry */
            list_push(i3->args, strdup(label));     /* label */
            /* 修改 i2: MOV Ry, A → MOV Ry, Rx */
            free(i2->args->head->next->elem);
            i2->args->head->next->elem = strdup(src0);  /* src = Rx */
            /* 删除 [0],[1]（从高到低） */
            remove_instr(instrs, start + 1);
            remove_instr(instrs, start + 0);
            return 2;
        }
    } else { /* is_jz */
        if (same_reg) {
            /* 模式 B1: 生成 DEC Rx; JZ label (替换 4 条为 2 条，节省 2) */
            /* 修改 i2: MOV Rx, A → DEC Rx */
            free(i2->op);
            i2->op = strdup("DEC");
            /* 修改参数：[Rx, A] → [Rx]（移除第二个参数） */
            if (i2->args->len >= 2) {
                ListNode* second = i2->args->head->next;
                if (second) {
                    free(second->elem);
                    i2->args->head->next = second->next;
                    if (second->next) second->next->prev = i2->args->head;
                    else i2->args->tail = i2->args->head;
                    free(second);
                    i2->args->len--;
                }
            }
            /* 删除 [0],[1]（从高到低） */
            remove_instr(instrs, start + 1);
            remove_instr(instrs, start + 0);
            return 2;
        } else {
            /* 模式 B2: 生成 MOV Ry, Rx; DEC Ry; JZ label (替换 4 条为 3 条，节省 1) */
            /* 修改 i2: MOV Ry, A → DEC Ry */
            free(i2->op);
            i2->op = strdup("DEC");
            if (i2->args->len >= 2) {
                ListNode* second = i2->args->head->next;
                if (second) {
                    free(second->elem);
                    i2->args->head->next = second->next;
                    if (second->next) second->next->prev = i2->args->head;
                    else i2->args->tail = i2->args->head;
                    free(second);
                    i2->args->len--;
                }
            }
            /* 修改 i1: DEC A → MOV Ry, Rx */
            free(i1->op);
            i1->op = strdup("MOV");
            /* 当前 i1->args 只有一个参数 "A"，需要改为 [Ry, Rx] */
            free(i1->args->head->elem);
            i1->args->head->elem = strdup(dst2);   /* Ry */
            list_push(i1->args, strdup(src0));      /* Rx */
            /* 删除 [0]（MOV A, Rx） */
            remove_instr(instrs, start + 0);
            return 1;
        }
    }
}

/* 窥孔优化：直接 MOV+DEC 循环 → DJNZ
 *
 * 模式（5条，R0-R7 直接 dec，不通过累加器 A）：
 *   Lloop:              [label at start]   ← 注：此处 Lloop 是当前 section 的循环头
 *   变体 A（5 条，DEC 的是目标 Rd）：
 *   [0] MOV Rd, Rs      (Rs, Rd 均为 R0-R7，且 Rd != Rs)
 *   [1] DEC Rd
 *   [2] JZ  Lexit       (或 JNZ Lloop)
 *   [3] MOV Rs, Rd      (phi 并行移动：把减后的值写回循环变量 Rs)
 *   [4] SJMP Lloop      (跳回循环头；Lloop 必须是 start 位置之前的标签)
 * →
 *   [0] DJNZ Rs, Lloop  (一条代替 5 条，节省 4)
 *
 *   变体 B（4 条，DEC 的是源 Rs，由 peephole_dec_reg_branch 5步变换后产生）：
 *   [0] MOV Ry, Rx      (Rx 是循环变量，Ry 是副本)
 *   [1] DEC Rx          (dec 源！与变体 A 不同)
 *   [2] JZ  Lexit
 *   [3] SJMP Lloop
 * →
 *   [0] MOV Ry, Rx (保留，供 Ry 使用)
 *   [1] DJNZ Rx, Lloop  (替换 [1][2][3]，节省 2)
 *
 *   注：DJNZ = DEC Rs; JNZ Lloop（非零则跳回），等价于原来的 while(--Rs)
 */
static int peephole_mov_dec_djnz(List* instrs, int start) {
    if (start < 1 || start + 3 >= instrs->len) return 0;

    AsmInstr* i_label = (AsmInstr*)list_get(instrs, start - 1);
    AsmInstr* i0 = (AsmInstr*)list_get(instrs, start);
    if (!i_label || !i0) return 0;
    /* 快速预检：i0 必须是 MOV，i_label 必须是标签 */
    if (!is_label_instr(i_label)) return 0;
    if (!is_mov(i0)) return 0;
    /* 标签的 op 形如 "L5:"，去掉末尾冒号得到标签名 */
    size_t llen = strlen(i_label->op);
    char lloop_buf[64];
    if (llen == 0 || llen >= sizeof(lloop_buf)) return 0;
    memcpy(lloop_buf, i_label->op, llen - 1);
    lloop_buf[llen - 1] = '\0';
    const char* lloop = lloop_buf;

    AsmInstr* i1 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* i2 = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* i3 = (AsmInstr*)list_get(instrs, start + 3);
    if (!i1 || !i2 || !i3) return 0;

    /* [0]: MOV Rd, Rs (Rd != Rs, 均为 R0-R7) */
    if (is_basic_block_barrier(i0) || !is_mov(i0)) return 0;
    const char* dst0 = get_operand(i0, 0);
    const char* src0 = get_operand(i0, 1);
    if (!dst0 || !src0) return 0;
    if (!(dst0[0]=='R' && dst0[1]>='0' && dst0[1]<='7' && dst0[2]=='\0')) return 0;
    if (!(src0[0]=='R' && src0[1]>='0' && src0[1]<='7' && src0[2]=='\0')) return 0;
    if (operands_equal(dst0, src0)) return 0; /* Rd == Rs 由其他 peephole 处理 */

    /* [1]: DEC ??? */
    if (is_basic_block_barrier(i1) || !i1->op || strcmp(i1->op, "DEC") != 0) return 0;
    const char* dec_arg = get_operand(i1, 0);
    if (!dec_arg) return 0;
    bool dec_is_dst = operands_equal(dec_arg, dst0); /* 变体 A: DEC Rd */
    bool dec_is_src = operands_equal(dec_arg, src0); /* 变体 B: DEC Rs */
    if (!dec_is_dst && !dec_is_src) return 0;

    /* [2]: JZ Lexit 或 JNZ Lloop */
    if (is_label_instr(i2) || !i2->op) return 0;
    bool is_jz  = (strcmp(i2->op, "JZ")  == 0);
    bool is_jnz = (strcmp(i2->op, "JNZ") == 0);
    if (!is_jz && !is_jnz) return 0;
    if (!i2->args || i2->args->len < 1) return 0;
    const char* i2_target = (const char*)list_get(i2->args, 0);
    if (!i2_target) return 0;

    /* ---- 变体 B（4条，dec_is_src）：MOV Ry,Rx; DEC Rx; JZ Lexit; SJMP/LJMP Lloop ---- */
    if (dec_is_src && is_jz) {
        /* [3]: SJMP/LJMP Lloop */
        if (!i3->op) return 0;
        bool i3_is_jump = (strcmp(i3->op, "SJMP") == 0 || strcmp(i3->op, "LJMP") == 0 ||
                          strcmp(i3->op, "AJMP") == 0 || strcmp(i3->op, "JMP")  == 0);
        if (!i3_is_jump) return 0;
        if (!i3->args || i3->args->len < 1) return 0;
        const char* sjmp_tgt = (const char*)list_get(i3->args, 0);
        if (!sjmp_tgt || !operands_equal(sjmp_tgt, lloop)) return 0;
        /* 变换：DEC Rx 改为 DJNZ Rx, Lloop；删除 [2] JZ, [3] SJMP */
        free(i1->op);
        i1->op = strdup("DJNZ");
        /* i1->args 从 [Rx] 改为 [Rx, Lloop] */
        list_push(i1->args, strdup(lloop));    /* Lloop */
        /* 从高到低删除：[3] SJMP, [2] JZ */
        remove_instr(instrs, start + 3);
        remove_instr(instrs, start + 2);
        return 2;
    }

    /* ---- 变体 A（5条，dec_is_dst）：MOV Rd,Rs; DEC Rd; JZ/JNZ; MOV Rs,Rd; SJMP/LJMP ---- */
    if (!dec_is_dst) return 0;
    if (start + 4 >= instrs->len) return 0;
    AsmInstr* i4 = (AsmInstr*)list_get(instrs, start + 4);
    if (!i4) return 0;

    /* [3]: MOV Rs, Rd (phi 并行移动) */
    if (is_basic_block_barrier(i3) || !is_mov(i3)) return 0;
    const char* dst3 = get_operand(i3, 0);
    const char* src3 = get_operand(i3, 1);
    if (!dst3 || !src3) return 0;
    if (!operands_equal(dst3, src0) || !operands_equal(src3, dst0)) return 0; /* MOV Rs, Rd */

    if (is_jz) {
        /* [4]: SJMP/LJMP Lloop（跳回循环头） */
        if (!i4->op) return 0;
        bool i4_is_jump = (strcmp(i4->op, "SJMP") == 0 || strcmp(i4->op, "LJMP") == 0 ||
                          strcmp(i4->op, "AJMP") == 0 || strcmp(i4->op, "JMP")  == 0);
        if (!i4_is_jump) return 0;
        if (!i4->args || i4->args->len < 1) return 0;
        const char* sjmp_tgt = (const char*)list_get(i4->args, 0);
        if (!sjmp_tgt || !operands_equal(sjmp_tgt, lloop)) return 0;

        /* 变换：JZ Lexit 改为 DJNZ Rs, Lloop；删除其余 4 条 */
        free(i2->op);
        i2->op = strdup("DJNZ");
        /* i2->args 从 [Lexit] 改为 [Rs, Lloop] */
        free(i2->args->head->elem);
        i2->args->head->elem = strdup(src0);   /* Rs */
        list_push(i2->args, strdup(lloop));    /* Lloop */
        /* 从高到低删除：[4] SJMP, [3] MOV Rs Rd, [1] DEC, [0] MOV Rd Rs */
        remove_instr(instrs, start + 4);
        remove_instr(instrs, start + 3);
        remove_instr(instrs, start + 1);
        remove_instr(instrs, start + 0);
        return 4;
    } else {
        /* is_jnz: [2] JNZ Lloop，确认 JNZ 跳回的是 Lloop */
        if (!operands_equal(i2_target, lloop)) return 0;
        /* 变换：JNZ Lloop → DJNZ Rs, Lloop；删除 [3] MOV Rs Rd, [1] DEC, [0] MOV Rd Rs */
        free(i2->op);
        i2->op = strdup("DJNZ");
        free(i2->args->head->elem);
        i2->args->head->elem = strdup(src0);   /* Rs */
        list_push(i2->args, strdup(lloop));    /* Lloop */
        remove_instr(instrs, start + 3);
        remove_instr(instrs, start + 1);
        remove_instr(instrs, start + 0);
        return 3;
    }
}

/* 窥孔优化：sbit bool 物化简化
 *
 * 模式：
 *   MOV C, sbit_addr    [0]   ; 加载 sbit 到 C
 *   CLR A               [1]   ; A = 0
 *   RLC A               [2]   ; A = C (A = 0 + C)
 *   MOV Rx, A           [3]   ; Rx = bool(sbit)
 * →
 *   CLR Rx              [0']  ; Rx = 0
 *   JNB sbit_addr, skip [1']  ; if sbit==0, skip
 *   MOV Rx, #1          [2']  ; Rx = 1
 *   skip:               [3']  (用下一条指令作为 skip target)
 *
 * 节省：4 条 → 3 条（+ 1 个标签，但 skip 可以直接接下一条）
 * 实际上：通过 JNB+fall-through 无需额外标签，直接跳过 MOV Rx,#1
 *
 * 更实用的变换（无需额外标签，3条）：
 *   CLR Rx
 *   JNB sbit_addr, Lskip
 *   MOV Rx, #1
 * Lskip:  (= 下一条指令)
 *
 * 因为下一条指令通常接着读 Rx，这 3 条是正确的。
 * 但需要一个 skip label，所以我们插入一个新的本地标签。
 *
 * 替代方案（完全无标签，2条，仅适用于 Rx 可通过 MOV 直接设）：
 * 其实最简洁的等价是保留这 4 条，依赖后续 peephole 消除冗余。
 *
 * 注意：`CLR C; RLC A` 已经被 peephole_clr_c_rlc_to_add 处理为 `ADD A, A`
 * 但这里是 `CLR A; RLC A`（先清 A，再 rotate through carry），不同！
 * CLR A → A=0；RLC A → A = (A<<1) | C = 0 | C = C（因 A 的位7进入C，但A=0时只有bit0=C）
 * 所以 `CLR A; RLC A` 确实等于 `A = C(原来的值)`（即 A = 0 or 1）。
 *
 * 生成方案（无新标签，利用 JNB 的 fall-through）：
 * 思路: 已有 peephole_clr_c_rlc_to_add 只处理 CLR C; RLC A。
 * 此处 CLR A; RLC A 是不同模式。
 *
 * 最简单的实现：将 4 条替换为 3 条：
 *   MOV C, sbit
 *   CLR Rx         (Rx = 0)
 *   RLC Rx         -- 不行，RLC 只对 A
 *
 * 正确方案：需要生成新标签。我们生成一个 __sbit_N 标签。
 * 或者更好：使用 ANL/ORL 绕过：
 *   CLR Rx
 *   MOV C, sbit
 *   RLC A          -- 还是需要 A
 *   MOV Rx, A      -- back to same problem
 *
 * 最终方案（3条，需 1 个跳过标签）：
 *   CLR Rx              ; Rx = 0
 *   JNB sbit_addr, $+4  ; 若 sbit=0 则跳过下一条（SJMP 相对+2 在 8051 汇编中）
 *   INC Rx              ; Rx = 1 (only if sbit=1)
 * 这样不需要显式标签，但需要汇编器支持 $+N 语法。
 *
 * 最稳定方案（使用 CLR A; MOV C, sbit; RLC A）：
 * 即保持 3 条，仅把 MOV C, sbit; CLR A; RLC A → CLR A; MOV C, sbit; RLC A
 * 再加 MOV Rx, A = 4 条。实际上是重排序，节省 0。
 *
 * 真正有效的方案：改变 `MOV C, sbit; CLR A; RLC A` 的整个语义，
 * 即：这 3 条 + MOV Rx, A = 4 条转换为 `CLR Rx; JNB sbit, skip; INC Rx; skip:`
 * = 3 条 + 1 个标签。净减少 1 条指令（4→3）。
 *
 * 我们使用一个静态计数器生成唯一的 skip 标签：__sbit_bool_N
 */
static int g_sbit_bool_counter = 0;

static int peephole_sbit_bool_materialize(List* instrs, int start) {
    if (start + 3 >= instrs->len) return 0;

    AsmInstr* i0 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* i1 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* i2 = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* i3 = (AsmInstr*)list_get(instrs, start + 3);
    if (!i0 || !i1 || !i2 || !i3) return 0;
    if (is_basic_block_barrier(i0) || is_basic_block_barrier(i1) ||
        is_basic_block_barrier(i2) || is_basic_block_barrier(i3)) return 0;

    /* [0]: MOV C, sbit_addr */
    if (!i0->op || strcmp(i0->op, "MOV") != 0) return 0;
    const char* dst0 = get_operand(i0, 0);
    const char* sbit_addr = get_operand(i0, 1);
    if (!dst0 || !sbit_addr) return 0;
    if (!operands_equal(dst0, "C")) return 0;
    /* sbit_addr must not be a register or immediate */
    if (is_register_operand(sbit_addr) || is_immediate_operand(sbit_addr)) return 0;

    /* [1]: CLR A */
    if (!i1->op || strcmp(i1->op, "CLR") != 0) return 0;
    const char* clr_arg = get_operand(i1, 0);
    if (!clr_arg || !operands_equal(clr_arg, "A")) return 0;

    /* [2]: RLC A */
    if (!i2->op || strcmp(i2->op, "RLC") != 0) return 0;
    const char* rlc_arg = get_operand(i2, 0);
    if (!rlc_arg || !operands_equal(rlc_arg, "A")) return 0;

    /* [3]: MOV Rx, A  (Rx = R0-R7) */
    if (!is_mov(i3)) return 0;
    const char* dst3 = get_operand(i3, 0);
    const char* src3 = get_operand(i3, 1);
    if (!dst3 || !src3) return 0;
    if (!(dst3[0] == 'R' && dst3[1] >= '0' && dst3[1] <= '7' && dst3[2] == '\0')) return 0;
    if (!operands_equal(src3, "A")) return 0;

    /* 生成唯一 skip 标签 */
    char skip_label[32];
    snprintf(skip_label, sizeof(skip_label), "__sbool_%d", g_sbit_bool_counter++);
    char skip_label_def[34];
    snprintf(skip_label_def, sizeof(skip_label_def), "%s:", skip_label);

    /* 构建替换指令序列（3条指令 + 1个标签定义）：
     *   CLR Rx
     *   JNB sbit_addr, skip_label
     *   INC Rx         (或 MOV Rx, #1，INC 更短: 2B vs 2B)
     * skip_label:
     */

    /* 新指令1: MOV Rx, #0 (CLR Rn is not a valid 8051 instruction) */
    AsmInstr* new_clr = calloc(1, sizeof(AsmInstr));
    new_clr->op = strdup("MOV");
    new_clr->args = make_list();
    list_push(new_clr->args, strdup(dst3));
    list_push(new_clr->args, strdup("#0"));

    /* 新指令2: JNB sbit_addr, skip_label */
    AsmInstr* new_jnb = calloc(1, sizeof(AsmInstr));
    new_jnb->op = strdup("JNB");
    new_jnb->args = make_list();
    list_push(new_jnb->args, strdup(sbit_addr));
    list_push(new_jnb->args, strdup(skip_label));

    /* 新指令3: INC Rx */
    AsmInstr* new_inc = calloc(1, sizeof(AsmInstr));
    new_inc->op = strdup("INC");
    new_inc->args = make_list();
    list_push(new_inc->args, strdup(dst3));

    /* 标签定义指令: skip_label: */
    AsmInstr* new_lbl = calloc(1, sizeof(AsmInstr));
    new_lbl->op = strdup(skip_label_def);
    new_lbl->args = make_list();

    /* 用 4 条新指令替换原来的 4 条
     * 先删除原来的 4 条（从高到低），再插入新的 4 条 */
    remove_instr(instrs, start + 3);
    remove_instr(instrs, start + 2);
    remove_instr(instrs, start + 1);
    remove_instr(instrs, start + 0);

    /* 从后往前插入（使最终顺序正确）*/
    insert_instr(instrs, start, new_lbl);
    insert_instr(instrs, start, new_inc);
    insert_instr(instrs, start, new_jnb);
    insert_instr(instrs, start, new_clr);

    /* 净指令数变化：4→4（相同数量），但消除了 A 寄存器的依赖，
     * 使后续 peephole 能进一步优化（如 JNB/JNZ 合并等）。
     * 原来: MOV C,sbit(2B) + CLR A(1B) + RLC A(1B) + MOV Rx,A(1B) = 5 bytes
     * 现在: CLR Rx(1B) + JNB sbit,lbl(3B) + INC Rx(1B) = 5 bytes
     * 字节数相同，但消除了 A 的依赖，使后续优化可合并 CJNE 序列。
     * 真正的节省来自后续 peephole 处理 CJNE 后面的比较零模式。
     */
    return 1; /* 标记发生了变化，触发再次迭代 */
}

/*
 * peephole_sbit_bool_jz: 合并 sbit-bool 化后的 JZ/JNZ 跳转
 *
 * 匹配模式（由 peephole_sbit_bool_materialize 生成）：
 *   [0]: CLR Rx
 *   [1]: JNB sbit, skip_lbl
 *   [2]: INC Rx
 *   [3]: skip_lbl:          (标签定义)
 *   [4]: MOV A, Rx
 *   [5]: JZ/JNZ target_lbl
 *
 * 转换：
 *   JNZ target → bit=1 时跳转 → JB sbit, target (节省 ~6 字节)
 *   JZ  target → bit=0 时跳转 → JNB sbit, target (节省 ~6 字节)
 *
 * 同时处理 JZ 变体：result 的逻辑
 *   Rx = (sbit != 0) ? 1 : 0
 *   JZ  Rx: 跳转如果 Rx==0, 即 sbit==0 → JNB sbit, target
 *   JNZ Rx: 跳转如果 Rx!=0, 即 sbit!=0 → JB  sbit, target
 */
static int peephole_sbit_bool_jz(List* instrs, int start) {
    if (start + 5 >= instrs->len) return 0;

    AsmInstr* i0 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* i1 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* i2 = (AsmInstr*)list_get(instrs, start + 2);
    AsmInstr* i3 = (AsmInstr*)list_get(instrs, start + 3);
    AsmInstr* i4 = (AsmInstr*)list_get(instrs, start + 4);
    AsmInstr* i5 = (AsmInstr*)list_get(instrs, start + 5);
    if (!i0 || !i1 || !i2 || !i3 || !i4 || !i5) return 0;

    /* [0]: CLR Rx */
    if (!i0->op || strcmp(i0->op, "CLR") != 0) return 0;
    const char* clr_reg = get_operand(i0, 0);
    if (!clr_reg || !IS_RX(clr_reg)) return 0;

    /* [1]: JNB sbit, skip_lbl */
    if (!i1->op || strcmp(i1->op, "JNB") != 0) return 0;
    const char* sbit_name = get_operand(i1, 0);
    const char* skip_lbl  = get_operand(i1, 1);
    if (!sbit_name || !skip_lbl) return 0;
    if (is_register_operand(sbit_name) || is_immediate_operand(sbit_name)) return 0;

    /* [2]: INC Rx (same Rx as [0]) */
    if (!i2->op || strcmp(i2->op, "INC") != 0) return 0;
    const char* inc_reg = get_operand(i2, 0);
    if (!inc_reg || !operands_equal(inc_reg, clr_reg)) return 0;

    /* [3]: skip_lbl: (label definition matching skip_lbl from [1]) */
    if (!is_label_instr(i3)) return 0;
    /* 标签定义形式为 "skip_lbl:" */
    size_t lbl_len = strlen(skip_lbl);
    if (strncmp(i3->op, skip_lbl, lbl_len) != 0) return 0;
    if (i3->op[lbl_len] != ':') return 0;

    /* [4]: MOV A, Rx */
    if (!is_mov(i4)) return 0;
    const char* mov_dst = get_operand(i4, 0);
    const char* mov_src = get_operand(i4, 1);
    if (!mov_dst || !mov_src) return 0;
    if (!operands_equal(mov_dst, "A")) return 0;
    if (!operands_equal(mov_src, clr_reg)) return 0;

    /* [5]: JZ target or JNZ target */
    if (!i5->op) return 0;
    bool is_jz  = (strcmp(i5->op, "JZ")  == 0);
    bool is_jnz = (strcmp(i5->op, "JNZ") == 0);
    if (!is_jz && !is_jnz) return 0;
    const char* target = get_operand(i5, 0);
    if (!target) return 0;

    /* 确保 skip_lbl 后面没有其他跳转目标指向 [3]（否则不安全删除标签）
     * 简单检查：skip_lbl 只在 [1] 使用（即 JNB 的目标）。
     * 只要在 [0..4] 之外没有其他指令跳转到 skip_lbl 即可。
     * 我们做一个保守检查：扫描整个 instrs，看是否有其他引用。
     */
    for (int j = 0; j < instrs->len; j++) {
        if (j >= start && j <= start + 5) continue; /* 跳过本模式本身 */
        AsmInstr* aj = (AsmInstr*)list_get(instrs, j);
        if (!aj) continue;
        if (!aj->args) continue;
        for (int k = 0; k < aj->args->len; k++) {
            const char* arg = (const char*)list_get(aj->args, k);
            if (arg && strcmp(arg, skip_lbl) == 0) return 0; /* 有其他引用，不安全 */
        }
    }

    /* 生成替换指令：
     *   JZ  target → JNB sbit, target   (sbit==0 时跳转)
     *   JNZ target → JB  sbit, target   (sbit==1 时跳转)
     */
    const char* new_op = is_jz ? "JNB" : "JB";

    AsmInstr* new_jb = calloc(1, sizeof(AsmInstr));
    new_jb->op = strdup(new_op);
    new_jb->args = make_list();
    list_push(new_jb->args, strdup(sbit_name));
    list_push(new_jb->args, strdup(target));

    /* 删除原来 6 条，插入 1 条 */
    for (int d = start + 5; d >= start; d--) {
        remove_instr(instrs, d);
    }
    insert_instr(instrs, start, new_jb);

    return 1;
}

/* 死代码删除：MOV Rx, src，Rx 后续不被读取则删除 */
static int peephole_dead_code(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!is_mov(ins)) return 0;
    const char* dst = get_operand(ins, 0);
    if (!IS_RX(dst)) return 0;
    if (!reg_read_before_write_or_end(instrs, start + 1, dst)) {
        remove_instr(instrs, start);
        return 1;
    }
    return 0;
}

/* 窥孔优化：删除无条件跳转/RET 后的死代码（跳转到下一个 label 之前的指令）
 * SJMP X + dead_instr → 直接删除 dead_instr
 * 例：SJMP L10; SJMP L11 → SJMP L10（第二个 SJMP 永远不执行）
 */
static int peephole_dead_after_jump(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;

    /* 当前指令必须是无条件控制转移（SJMP/LJMP/AJMP/RET/RETI）*/
    bool is_uncond = (strcmp(ins->op,"SJMP")==0 || strcmp(ins->op,"LJMP")==0 ||
                      strcmp(ins->op,"AJMP")==0 || strcmp(ins->op,"RET")==0  ||
                      strcmp(ins->op,"RETI")==0);
    if (!is_uncond) return 0;

    AsmInstr* next = (AsmInstr*)list_get(instrs, start + 1);
    if (!next || !next->op) return 0;

    /* 下一条必须不是 label（label 是可达的）*/
    size_t nlen = strlen(next->op);
    if (nlen > 0 && next->op[nlen - 1] == ':') return 0;

    /* 删除下一条（死代码）*/
    remove_instr(instrs, start + 1);
    return 1;
}

/* 返回条件指令的逆条件 */
static const char* invert_cond(const char* op) {
    if (!op) return NULL;
    if (strcmp(op, "JZ")  == 0) return "JNZ";
    if (strcmp(op, "JNZ") == 0) return "JZ";
    if (strcmp(op, "JC")  == 0) return "JNC";
    if (strcmp(op, "JNC") == 0) return "JC";
    return NULL;
}

/* 窥孔优化：Jcond Lskip; SJMP/LJMP L2; Lskip: → Jinv_cond L2
 * 将条件跳转绕过无条件跳转的模式折叠为单个反向条件跳转。
 * 例：JZ Lskip; SJMP L2; Lskip: → JNZ L2
 */
static int peephole_fold_cond_jump(List* instrs, int start) {
    if (start + 2 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    AsmInstr* ins3 = (AsmInstr*)list_get(instrs, start + 2);

    if (!ins1 || !ins2 || !ins3 || !ins1->op || !ins2->op || !ins3->op) return 0;

    /* ins1 必须是单操作数条件跳转（JZ/JNZ/JC/JNC） */
    const char* inv = invert_cond(ins1->op);
    if (!inv) return 0;
    if (!ins1->args || ins1->args->len < 1) return 0;
    const char* skip_target = (const char*)list_get(ins1->args, 0);
    if (!skip_target) return 0;

    /* ins2 必须是无条件跳转 SJMP/LJMP/AJMP */
    if (!(strcmp(ins2->op, "SJMP") == 0 || strcmp(ins2->op, "LJMP") == 0 || strcmp(ins2->op, "AJMP") == 0)) return 0;
    if (!ins2->args || ins2->args->len < 1) return 0;
    const char* jump_target = (const char*)list_get(ins2->args, 0);
    if (!jump_target) return 0;

    /* ins3 必须是 ins1 的 skip 目标标签 */
    size_t len3 = strlen(ins3->op);
    if (len3 == 0 || ins3->op[len3 - 1] != ':') return 0;
    char label3[64];
    if (len3 >= sizeof(label3)) return 0;
    strncpy(label3, ins3->op, len3 - 1);
    label3[len3 - 1] = '\0';
    if (strcmp(skip_target, label3) != 0) return 0;

    /* 检查 label3 是否还有其他引用（除了 ins1 本身） */
    int ref_count = 0;
    for (int i = 0; i < instrs->len; i++) {
        AsmInstr* check = (AsmInstr*)list_get(instrs, i);
        if (!check || !check->args) continue;
        for (int j = 0; j < check->args->len; j++) {
            const char* arg = (const char*)list_get(check->args, j);
            if (arg && strcmp(arg, label3) == 0) ref_count++;
        }
    }
    /* 如果 label3 还被其他指令引用，不能直接删除标签，但仍可以折叠跳转 */

    /* 将 ins1 的操作改为反向条件跳转，目标改为 jump_target */
    free(ins1->op);
    ins1->op = strdup(inv);
    free(ins1->args->head->elem);
    ins1->args->head->elem = strdup(jump_target);

    /* 删除 ins2（原无条件跳转） */
    remove_instr(instrs, start + 1);

    /* 如果 label3 只被这一处引用，也删除标签（现在 ins3 在位置 start+1） */
    if (ref_count <= 1) {
        remove_instr(instrs, start + 1);
    }

    return 1;
}

/* 窥孔优化：Jcond X; SJMP Y → Jinv_cond Y
 * 当 Jcond X + SJMP Y 且下一指令不是 X: 时（即不能用 fold_cond_jump 折叠），
 * 直接反转条件、目标改为 Y、删除 SJMP，保留 X 的 label。
 * 例：JNZ L12; SJMP L13; L11: → JZ L13; L11:
 */
static int peephole_invert_cond_over_jump(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);

    if (!ins1 || !ins2 || !ins1->op || !ins2->op) return 0;

    /* ins1: JZ/JNZ/JC/JNC */
    const char* inv = invert_cond(ins1->op);
    if (!inv) return 0;
    if (!ins1->args || ins1->args->len < 1) return 0;
    const char* skip_target = (const char*)list_get(ins1->args, 0);
    if (!skip_target) return 0;

    /* ins2: SJMP/LJMP/AJMP */
    if (!(strcmp(ins2->op, "SJMP") == 0 || strcmp(ins2->op, "LJMP") == 0 || strcmp(ins2->op, "AJMP") == 0)) return 0;
    if (!ins2->args || ins2->args->len < 1) return 0;
    const char* jump_target = (const char*)list_get(ins2->args, 0);
    if (!jump_target) return 0;

    /* 如果 ins3 紧接是 skip_target 的 label，fold_cond_jump 已处理，跳过 */
    if (start + 2 < instrs->len) {
        AsmInstr* ins3 = (AsmInstr*)list_get(instrs, start + 2);
        if (ins3 && ins3->op) {
            size_t len3 = strlen(ins3->op);
            if (len3 > 1 && ins3->op[len3 - 1] == ':') {
                char label3[64];
                if (len3 < sizeof(label3)) {
                    strncpy(label3, ins3->op, len3 - 1);
                    label3[len3 - 1] = '\0';
                    if (strcmp(skip_target, label3) == 0) return 0; /* fold_cond_jump 会处理 */
                }
            }
        }
    }

    /* 折叠：反转条件，目标改为 jump_target，删除 SJMP */
    free(ins1->op);
    ins1->op = strdup(inv);
    free(ins1->args->head->elem);
    ins1->args->head->elem = strdup(jump_target);
    remove_instr(instrs, start + 1);
    return 1;
}

/* 窥孔优化：删除 MOV Rn, Rn（自赋值） */
static int peephole_self_mov(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!is_mov(ins)) return 0;
    const char* dst = get_operand(ins, 0);
    const char* src = get_operand(ins, 1);
    if (!dst || !src) return 0;
    if (strcmp(dst, src) == 0) {
        remove_instr(instrs, start);
        return 1;
    }
    return 0;
}

static int peephole_jump_to_next_label(List* instrs, int start) {
    AsmInstr* ins;
    AsmInstr* next;
    const char* target;
    char label[64];

    if (start + 1 >= instrs->len) return 0;

    ins = (AsmInstr*)list_get(instrs, start);
    next = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins || !next || !ins->op || !next->op) return 0;
    if (!(strcmp(ins->op, "SJMP") == 0 || strcmp(ins->op, "LJMP") == 0 || strcmp(ins->op, "AJMP") == 0)) return 0;
    if (!ins->args || ins->args->len < 1) return 0;
    target = (const char*)list_get(ins->args, 0);
    if (!target) return 0;
    if (!get_label_name(next, label, sizeof(label))) return 0;

    if (strcmp(target, label) == 0) {
        remove_instr(instrs, start);
        return 1;
    }

    return 0;
}

static int peephole_jump_to_following_label_cluster(List* instrs, int start) {
    AsmInstr* ins;
    const char* target;

    if (start + 1 >= instrs->len) return 0;

    ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;
    if (!(strcmp(ins->op, "SJMP") == 0 || strcmp(ins->op, "LJMP") == 0 || strcmp(ins->op, "AJMP") == 0)) return 0;
    if (!ins->args || ins->args->len < 1) return 0;
    target = (const char*)list_get(ins->args, 0);
    if (!target) return 0;

    for (int i = start + 1; i < instrs->len; i++) {
        AsmInstr* next = (AsmInstr*)list_get(instrs, i);
        char label[64];

        if (!next || !next->op) break;
        if (!get_label_name(next, label, sizeof(label))) break;
        if (strcmp(target, label) == 0) {
            remove_instr(instrs, start);
            return 1;
        }
    }

    return 0;
}

/* 窥孔优化：条件跳转 threading
 * Jcond TARGET; ... TARGET: SJMP Y → Jcond Y
 * 当 TARGET 标签后紧跟的是无条件跳转 SJMP/LJMP/AJMP 时，
 * 直接把条件跳转的目标替换为 Y（穿透跳转链）。
 * 例：JB ACC.7, Lcmp_true_1 + Lcmp_true_1: SJMP L11 → JB ACC.7, L11
 */
static int peephole_thread_cond_jump(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;

    /* 必须是单操作数条件跳转：JZ/JNZ/JC/JNC，或双/三操作数末尾是 label 的
     * 这里只处理 JZ/JNZ/JC/JNC/JB/JNB 且第一个（或最后一个）操作数是 label */
    const char* op = ins->op;
    bool is_single_cond = (strcmp(op,"JZ")==0 || strcmp(op,"JNZ")==0 ||
                           strcmp(op,"JC")==0 || strcmp(op,"JNC")==0);
    bool is_bit_cond    = (strcmp(op,"JB")==0 || strcmp(op,"JNB")==0 || strcmp(op,"JBC")==0);
    if (!is_single_cond && !is_bit_cond) return 0;
    if (!ins->args || ins->args->len < 1) return 0;

    /* 目标 label 是最后一个操作数 */
    const char* target = (const char*)list_get(ins->args, ins->args->len - 1);
    if (!target) return 0;

    /* 向前找 target 标签，紧跟一条无条件跳转 */
    for (int i = start + 1; i + 1 < instrs->len; i++) {
        AsmInstr* label_ins = (AsmInstr*)list_get(instrs, i);
        char label[64];
        if (!get_label_name(label_ins, label, sizeof(label))) continue;
        if (strcmp(label, target) != 0) continue;

        /* 找到 label，检查紧跟的指令 */
        AsmInstr* jump_ins = (AsmInstr*)list_get(instrs, i + 1);
        if (!jump_ins || !jump_ins->op) return 0;
        if (!(strcmp(jump_ins->op, "SJMP") == 0 || strcmp(jump_ins->op, "LJMP") == 0 || strcmp(jump_ins->op, "AJMP") == 0)) return 0;
        if (!jump_ins->args || jump_ins->args->len < 1) return 0;
        const char* chained_target = (const char*)list_get(jump_ins->args, 0);
        if (!chained_target || strcmp(chained_target, target) == 0) return 0;

        /* 更新条件跳转的目标 */
        ListNode* n = ins->args->head;
        for (int k = 0; k < ins->args->len - 1; k++) n = n->next;
        free(n->elem);
        n->elem = strdup(chained_target);
        return 1;
    }
    return 0;
}

static int peephole_thread_jump_chain(List* instrs, int start) {
    AsmInstr* ins;
    const char* target;

    if (start + 2 >= instrs->len) return 0;

    ins = (AsmInstr*)list_get(instrs, start);
    if (!ins || !ins->op) return 0;
    if (!(strcmp(ins->op, "SJMP") == 0 || strcmp(ins->op, "LJMP") == 0 || strcmp(ins->op, "AJMP") == 0)) return 0;
    if (!ins->args || ins->args->len < 1) return 0;
    target = (const char*)list_get(ins->args, 0);
    if (!target) return 0;

    for (int i = start + 1; i + 1 < instrs->len; i++) {
        AsmInstr* label_ins = (AsmInstr*)list_get(instrs, i);
        AsmInstr* jump_ins = (AsmInstr*)list_get(instrs, i + 1);
        char label[64];
        const char* chained_target;

        if (!get_label_name(label_ins, label, sizeof(label))) continue;
        if (strcmp(label, target) != 0) continue;
        if (!jump_ins || !jump_ins->op) return 0;
        if (!(strcmp(jump_ins->op, "SJMP") == 0 || strcmp(jump_ins->op, "LJMP") == 0 || strcmp(jump_ins->op, "AJMP") == 0)) return 0;
        if (!jump_ins->args || jump_ins->args->len < 1) return 0;
        chained_target = (const char*)list_get(jump_ins->args, 0);
        if (!chained_target || strcmp(chained_target, target) == 0) return 0;

        free(ins->args->head->elem);
        ins->args->head->elem = strdup(chained_target);
        return 1;
    }

    return 0;
}

/* 辅助函数：比较两条指令是否等价（op 和 args 完全相同，忽略注释） */
static bool asm_instrs_equal(AsmInstr* a, AsmInstr* b) {
    if (!a || !b) return false;
    if (!a->op || !b->op) return false;
    if (strcmp(a->op, b->op) != 0) return false;
    int na = a->args ? a->args->len : 0;
    int nb = b->args ? b->args->len : 0;
    if (na != nb) return false;
    for (int i = 0; i < na; i++) {
        const char* aa = (const char*)list_get(a->args, i);
        const char* ba = (const char*)list_get(b->args, i);
        if (!aa || !ba) return false;
        if (strcmp(aa, ba) != 0) return false;
    }
    return true;
}

/* 辅助函数：复制一条指令（浅复制 op 和 args，不复制注释） */
static AsmInstr* asm_instr_clone(AsmInstr* src) {
    if (!src) return NULL;
    AsmInstr* dst = calloc(1, sizeof(AsmInstr));
    if (!dst) return NULL;
    dst->op = src->op ? strdup(src->op) : NULL;
    dst->args = make_list();
    if (src->args) {
        for (int i = 0; i < src->args->len; i++) {
            const char* a = (const char*)list_get(src->args, i);
            list_push(dst->args, a ? strdup(a) : strdup(""));
        }
    }
    return dst;
}

/* 窥孔优化：提升两路相同代码到条件跳转之前
 * 模式：
 *   Jcond L_true
 *   [N 条相同的 MOV，称 A1..AN]
 *   SJMP L_false
 * L_true:
 *   [N 条相同的 MOV，称 B1..BN，与 A1..AN 完全相同]
 *   SJMP L_other  (或 fallthrough)
 *
 * 变换为：
 *   [A1..AN]          ← 提升到条件跳转之前
 *   Jinv_cond L_false ← 反转条件，跳到原 false 路
 *   SJMP L_other      ← 保留 true 路跳转（会被 dead_after_jump 等继续优化）
 *
 * 节省：删掉 false 路 N 条 MOV + false SJMP + L_true 标签 + true 路 N 条 MOV，
 *       插入 N 条提升 MOV，净节省 2N+2-N = N+2 条
 */
static int peephole_hoist_common_code_over_branch(List* instrs, int start) {
    if (start + 4 >= instrs->len) return 0;

    AsmInstr* jcond = (AsmInstr*)list_get(instrs, start);
    if (!jcond || !jcond->op) return 0;

    /* ins1: JZ/JNZ/JC/JNC（单操作数条件跳转） */
    const char* inv = invert_cond(jcond->op);
    if (!inv) return 0;
    if (!jcond->args || jcond->args->len != 1) return 0;
    const char* l_true_target = (const char*)list_get(jcond->args, 0);
    if (!l_true_target) return 0;

    /* 扫描 false 路：找 N 条 MOV，再跟一条 SJMP */
    int n = 0;
    int false_sjmp_idx = -1;
    const char* l_false_target = NULL;
    #define MAX_HOIST 4
    int false_mov_idx[MAX_HOIST];

    for (int j = start + 1; j < instrs->len && n <= MAX_HOIST; j++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, j);
        if (!ins || !ins->op) break;
        /* 遇到标签 → false 路结束（没有找到 SJMP） */
        size_t oplen = strlen(ins->op);
        if (oplen > 0 && ins->op[oplen - 1] == ':') break;
        /* 遇到 SJMP/LJMP/AJMP → 这是 false 路的最终跳转 */
        if (strcmp(ins->op, "SJMP") == 0 || strcmp(ins->op, "LJMP") == 0 || strcmp(ins->op, "AJMP") == 0) {
            if (!ins->args || ins->args->len < 1) break;
            l_false_target = (const char*)list_get(ins->args, 0);
            false_sjmp_idx = j;
            break;
        }
        /* 只允许 MOV 指令（其他指令不能安全提升） */
        if (!is_mov(ins)) break;
        /* 提升的 MOV 不能写 A（会影响后续条件跳转的标志/操作数） */
        const char* dst = get_operand(ins, 0);
        if (dst && operands_equal(dst, "A")) break;
        /* 记录这条 MOV */
        if (n < MAX_HOIST) {
            false_mov_idx[n] = j;
            n++;
        }
    }

    if (n == 0 || false_sjmp_idx < 0 || !l_false_target) return 0;
    /* false 路必须紧跟在条件跳转后（false_mov_idx[0] == start+1） */
    if (false_mov_idx[0] != start + 1) return 0;

    /* 在 false_sjmp 之后寻找 L_true: 标签（允许最多 1 步） */
    int label_idx = -1;
    for (int j = false_sjmp_idx + 1; j < instrs->len && j <= false_sjmp_idx + 2; j++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, j);
        char label_name[64];
        if (!get_label_name(ins, label_name, sizeof(label_name))) break;
        if (strcmp(label_name, l_true_target) == 0) { label_idx = j; break; }
    }
    if (label_idx < 0) return 0;

    /* true 路：紧跟 L_true: 标签后的 N 条指令必须与 false 路完全相同 */
    if (label_idx + n >= instrs->len) return 0;
    for (int k = 0; k < n; k++) {
        AsmInstr* fa = (AsmInstr*)list_get(instrs, false_mov_idx[k]);
        AsmInstr* ta = (AsmInstr*)list_get(instrs, label_idx + 1 + k);
        if (!asm_instrs_equal(fa, ta)) return 0;
    }

    /* 确认 L_true 标签只被 jcond 引用（其他引用 = 不安全） */
    int ref_count = 0;
    for (int j = 0; j < instrs->len; j++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, j);
        if (!ins || !ins->args) continue;
        for (int a = 0; a < ins->args->len; a++) {
            const char* arg = (const char*)list_get(ins->args, a);
            if (arg && strcmp(arg, l_true_target) == 0) ref_count++;
        }
    }
    if (ref_count > 1) return 0; /* 有多于 1 处引用，不安全 */

    /* 所有条件满足，执行变换 */

    /* 步骤 1：在 start 之前插入 N 条 MOV（提升到条件跳转之前） */
    for (int k = 0; k < n; k++) {
        /* 每次插入后索引向后偏移 1，所以 false_mov_idx[k] 对应当前的 false_mov_idx[k]+k */
        AsmInstr* fa = (AsmInstr*)list_get(instrs, false_mov_idx[k] + k);
        AsmInstr* cloned = asm_instr_clone(fa);
        if (!cloned) return 0;
        insert_instr(instrs, start + k, cloned);
    }
    /* 插入 N 条后，所有后续索引 +N */
    int jcond_new      = start + n;
    int false_mov_base = jcond_new + 1;           /* false 路 MOV 的起始 */
    int false_sjmp_new = false_sjmp_idx + n;      /* false SJMP */
    int label_new      = label_idx + n;           /* L_true: */
    int true_mov_base  = label_new + 1;           /* true 路 MOV 的起始 */

    /* 步骤 2：把 jcond 改为反转条件，目标改为 l_false_target */
    AsmInstr* jcond_ins = (AsmInstr*)list_get(instrs, jcond_new);
    free(jcond_ins->op);
    jcond_ins->op = strdup(inv);
    free(jcond_ins->args->head->elem);
    jcond_ins->args->head->elem = strdup(l_false_target);

    /* 步骤 3：从后往前删除 true 路 N 条 MOV */
    for (int k = n - 1; k >= 0; k--) {
        remove_instr(instrs, true_mov_base + k);
    }

    /* 步骤 4：删掉 L_true: 标签（true_mov_base 减 N 后就是 label_new）*/
    remove_instr(instrs, label_new);

    /* 步骤 5：删掉 false SJMP */
    remove_instr(instrs, false_sjmp_new);

    /* 步骤 6：从后往前删除 false 路 N 条 MOV */
    for (int k = n - 1; k >= 0; k--) {
        remove_instr(instrs, false_mov_base + k);
    }

    /* 净节省：插入 N，删掉 N(false) + 1(SJMP) + 1(label) + N(true) = 2N+2，净减少 N+2 */
    return n + 2;
}

/* IDATA dead spill store elimination
 * A spill symbol __spill_N is "dead" if it is only stored (MOV __spill_N, A)
 * but never loaded or used as a source operand.
 * Returns total number of instructions removed.
 */
static int eliminate_dead_idata_spills(List* instrs) {
    if (!instrs) return 0;

    /* Step 1: collect all spill symbols that are USED (appear as src) */
    char used_spills[128][64];
    int used_cnt = 0;

    for (int i = 0; i < instrs->len; i++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, i);
        if (!ins || !ins->args) continue;
        int start_arg = 0;
        if (ins->op && strcmp(ins->op, "MOV") == 0 && ins->args->len >= 2) {
            start_arg = 1; /* skip dst */
        }
        for (int a = start_arg; a < ins->args->len; a++) {
            const char* arg = (const char*)list_get(ins->args, a);
            if (!arg) continue;
            const char* s = arg;
            if (*s == '(') s++;
            if (strncmp(s, "__spill_", 8) != 0) continue;
            const char* end = s;
            while (*end && *end != ' ' && *end != '+' && *end != ')') end++;
            size_t sym_len = end - s;
            if (sym_len == 0 || sym_len >= 64) continue;
            char sym[64];
            strncpy(sym, s, sym_len);
            sym[sym_len] = '\0';
            bool dup = false;
            for (int j = 0; j < used_cnt; j++) {
                if (strcmp(used_spills[j], sym) == 0) { dup = true; break; }
            }
            if (!dup && used_cnt < 128) {
                strncpy(used_spills[used_cnt], sym, 63);
                used_spills[used_cnt][63] = '\0';
                used_cnt++;
            }
        }
    }

    /* Step 2: remove dead stores */
    int total_removed = 0;
    int dead_removed = 1;
    while (dead_removed) {
        dead_removed = 0;
        for (int i = 0; i < instrs->len; i++) {
            AsmInstr* ins = (AsmInstr*)list_get(instrs, i);
            if (!ins || !is_mov(ins)) continue;
            const char* dst = get_operand(ins, 0);
            const char* src = get_operand(ins, 1);
            if (!dst || !src) continue;
            if (!operands_equal(src, "A")) continue;
            if (is_indirect_operand(dst)) continue;
            const char* s = dst;
            if (*s == '(') s++;
            if (strncmp(s, "__spill_", 8) != 0) continue;
            const char* end = s;
            while (*end && *end != ' ' && *end != '+' && *end != ')') end++;
            size_t sym_len = end - s;
            if (sym_len == 0 || sym_len >= 64) continue;
            char sym[64];
            strncpy(sym, s, sym_len);
            sym[sym_len] = '\0';
            bool is_used = false;
            for (int j = 0; j < used_cnt; j++) {
                if (strcmp(used_spills[j], sym) == 0) { is_used = true; break; }
            }
            if (is_used) continue;
            remove_instr(instrs, i);
            dead_removed++;
            total_removed++;
            break;
        }
    }
    return total_removed;
}

/* XDATA 死存储消除：6条 store 序列且对应地址从不被加载时删除 */
static void eliminate_dead_xdata_stores(List* instrs) {
    /* 收集所有被加载的 XDATA 地址基名 */
    char loaded[64][128];
    int loaded_cnt = 0;
    for (int i = 0; i + 1 < instrs->len && loaded_cnt < 64; i++) {
        AsmInstr* a = (AsmInstr*)list_get(instrs, i);
        AsmInstr* b = (AsmInstr*)list_get(instrs, i + 1);
        if (!a || !b || !is_mov(a)) continue;
        if (!operands_equal(get_operand(a, 0), "DPTR")) continue;
        const char* addr = get_operand(a, 1);
        if (!addr || addr[0] != '#') continue;
        if (!b->op || strcmp(b->op, "MOVX") != 0) continue;
        if (!operands_equal(get_operand(b, 0), "A")) continue;

        const char* s = addr + 1;
        if (*s == '(') s++;
        const char* end = s;
        while (*end && *end != ' ' && *end != '+' && *end != ')') end++;
        size_t sym_len = end - s;
        if (!sym_len || sym_len >= 128) continue;
        char sym[128]; memcpy(sym, s, sym_len); sym[sym_len] = '\0';
        bool dup = false;
        for (int j = 0; j < loaded_cnt; j++) if (strcmp(loaded[j], sym)==0) { dup=true; break; }
        if (!dup) { strncpy(loaded[loaded_cnt], sym, 127); loaded[loaded_cnt++][127]='\0'; }
    }

    int dead_removed;
    do {
        dead_removed = 0;
        for (int i = 0; i + 5 < instrs->len; i++) {
            AsmInstr* i0 = (AsmInstr*)list_get(instrs, i);
            AsmInstr* i1 = (AsmInstr*)list_get(instrs, i + 1);
            AsmInstr* i2 = (AsmInstr*)list_get(instrs, i + 2);
            AsmInstr* i3 = (AsmInstr*)list_get(instrs, i + 3);
            AsmInstr* i4 = (AsmInstr*)list_get(instrs, i + 4);
            AsmInstr* i5 = (AsmInstr*)list_get(instrs, i + 5);
            if (!i0||!i1||!i2||!i3||!i4||!i5) continue;
            if (!is_mov(i0) || !operands_equal(get_operand(i0,0),"DPTR")) continue;
            const char* a0 = get_operand(i0, 1);
            if (!a0 || a0[0] != '#') continue;
            if (!is_mov(i1) || !operands_equal(get_operand(i1,0),"A")) continue;
            if (!i2->op || strcmp(i2->op,"MOVX")!=0 ||
                !operands_equal(get_operand(i2,0),"@DPTR")) continue;
            if (!is_mov(i3) || !operands_equal(get_operand(i3,0),"DPTR")) continue;
            if (!is_mov(i4) || !operands_equal(get_operand(i4,0),"A")) continue;
            if (!i5->op || strcmp(i5->op,"MOVX")!=0 ||
                !operands_equal(get_operand(i5,0),"@DPTR")) continue;

            const char* s = a0 + 1;
            if (*s == '(') s++;
            const char* end = s;
            while (*end && *end != ' ' && *end != '+' && *end != ')') end++;
            size_t sym_len = end - s;
            if (!sym_len || sym_len >= 128) continue;
            char sym[128]; memcpy(sym, s, sym_len); sym[sym_len] = '\0';

            bool is_loaded = false;
            for (int j = 0; j < loaded_cnt; j++)
                if (strcmp(loaded[j], sym)==0) { is_loaded=true; break; }
            if (is_loaded) continue;

            for (int k = 5; k >= 0; k--) remove_instr(instrs, i + k);
            dead_removed++;
            break;
        }
    } while (dead_removed);
}

/* 对单个section执行窥孔优化 */
static void optimize_section(Section* sec) {
    if (!sec || !sec->asminstrs) return;

    int changed = 1;
    int iterations = 0;
    const int max_iterations = 12;

    while (changed && iterations < max_iterations) {
        changed = 0;
        iterations++;

        for (int i = 0; i < sec->asminstrs->len; i++) {
            int removed = 0;

            removed = peephole_remove_empty_local_label(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_add_zero_16(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_add_addc_zero(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_anl_bit0_branch(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_logical_nop(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            // CLR C; RLC A → ADD A, A (逻辑左移1位，节省1条指令)
            removed = peephole_clr_c_rlc_to_add(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_orl_with_zero_acc(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_drop_dead_mov_before_bit_branch(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_dead_mov_a(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_fold_mov_a_to_mem(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_copy_pair_fold(sec->asminstrs, i);
            if (removed) { changed = 1; i += removed - 1; continue; }

            removed = peephole_redundant_swap(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_redundant_load(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_eliminate_temp_reg(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_copy_propagate(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_forward_copy_to_dest(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_idata_store_load_forward(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_idata_load_from_reg(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_spill16_store_reload_forward(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_xdata_store_load_forward(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_dec_reg_branch(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_dec_djnz(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_sbit_bool_materialize(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_sbit_bool_jz(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_reg_to_any(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_propagate_reg_imm(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_chain(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_dead_code(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_dead_after_jump(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_self_mov(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            /* Control-flow peepholes here are currently too aggressive and can
             * collapse live blocks (e.g. branch true-path arithmetic blocks in
             * `test_isel_branch`). Keep them disabled until their CFG safety
             * conditions are fixed. */
        }

        if (eliminate_dead_idata_spills(sec->asminstrs) > 0) changed = 1;
    }

    eliminate_dead_xdata_stores(sec->asminstrs);
}

void c51_optimize(C51GenContext* ctx, ObjFile* obj)
{
    (void)ctx;
    (void)obj;
    if (!obj || !obj->sections) return;
    if (getenv("C51CC_REGDEBUG"))
        fprintf(stderr, "[c51_optimize] called (C51CC_NO_OPT=%s)\n", getenv("C51CC_NO_OPT") ? getenv("C51CC_NO_OPT") : "NULL");

    // 对每个节执行窥孔优化（仅对含有 asminstrs 的节）
    for (int i = 0; i < obj->sections->len; i++) {
        Section *sec = (Section*)list_get(obj->sections, i);
        if (!sec) continue;
        if (sec->asminstrs && sec->asminstrs->len > 0) {
            optimize_section(sec);
        }
    }
}

/* 判断操作数是否是寄存器（R0-R7 或 A） */
static bool is_register_operand(const char* op) {
    if (!op) return false;
    if (strcmp(op, "A") == 0) return true;
    if (op[0] == 'R' && op[1] >= '0' && op[1] <= '7' && op[2] == '\0') return true;
    return false;
}

/* 判断操作数是否是立即数（以 '#' 开头） */
static bool is_immediate_operand(const char* op) {
    if (!op) return false;
    return op[0] == '#';
}

/* 判断是否可能是内存或 SFR 操作数（保守判断：非寄存器且非立即即视为内存） */
static bool is_memory_operand(const char* op) {
    if (!op) return false;
    return !is_register_operand(op) && !is_immediate_operand(op);
}

/* 在列表任意位置插入指令 */
static void insert_instr(List* instrs, int index, AsmInstr* ins) {
    if (!instrs || !ins) return;
    if (index <= 0) {
        list_unshift(instrs, ins);
        return;
    }
    if (index >= instrs->len) {
        list_push(instrs, ins);
        return;
    }

    ListNode *n = instrs->head;
    for (int i = 0; i < index; i++) n = n->next;
    ListNode *node = make_node(ins);
    node->next = n;
    node->prev = n->prev;
    if (n->prev) n->prev->next = node;
    else instrs->head = node;
    n->prev = node;
    instrs->len++;
}

