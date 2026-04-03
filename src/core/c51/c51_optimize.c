#include "c51_optimize.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* 检查两个操作数是否相同 */
static bool operands_equal(const char* op1, const char* op2) {
    if (!op1 || !op2) return false;
    return strcmp(op1, op2) == 0;
}

/* 获取指令的操作数 */
static const char* get_operand(AsmInstr* ins, int index) {
    if (!ins || !ins->args || index >= ins->args->len) return NULL;
    return (const char*)list_get(ins->args, index);
}

/* 检查指令是否是 MOV */
static bool is_mov(AsmInstr* ins) {
    return ins && ins->op && strcmp(ins->op, "MOV") == 0;
}

static bool is_label_instr(AsmInstr* ins) {
    if (!ins || !ins->op) return false;
    size_t len = strlen(ins->op);
    return len > 0 && ins->op[len - 1] == ':';
}

static bool is_control_transfer_instr(AsmInstr* ins) {
    if (!ins || !ins->op) return false;
    return strcmp(ins->op, "SJMP") == 0 ||
           strcmp(ins->op, "AJMP") == 0 ||
           strcmp(ins->op, "LJMP") == 0 ||
           strcmp(ins->op, "JMP") == 0 ||
           strcmp(ins->op, "JC") == 0 ||
           strcmp(ins->op, "JNC") == 0 ||
           strcmp(ins->op, "JZ") == 0 ||
           strcmp(ins->op, "JNZ") == 0 ||
           strcmp(ins->op, "CJNE") == 0 ||
           strcmp(ins->op, "DJNZ") == 0 ||
           strcmp(ins->op, "JB") == 0 ||
           strcmp(ins->op, "JNB") == 0 ||
           strcmp(ins->op, "JBC") == 0 ||
           strcmp(ins->op, "RET") == 0 ||
           strcmp(ins->op, "RETI") == 0 ||
           strcmp(ins->op, "ACALL") == 0 ||
           strcmp(ins->op, "LCALL") == 0 ||
           strcmp(ins->op, "CALL") == 0;
}

static bool is_basic_block_barrier(AsmInstr* ins) {
    return is_label_instr(ins) || is_control_transfer_instr(ins);
}

/* 前向声明：操作数类型检查 */
static bool is_register_operand(const char* op);
static bool is_immediate_operand(const char* op);
static bool is_memory_operand(const char* op);

/* 检查寄存器是否在指令中被使用 */
static bool reg_used_in_instr(AsmInstr* ins, const char* reg) {
    if (!ins || !reg) return false;
    if (ins->args) {
        for (int i = 0; i < ins->args->len; i++) {
            const char* arg = (const char*)list_get(ins->args, i);
            if (arg && strcmp(arg, reg) == 0) return true;
        }
    }
    return false;
}

static bool operand_reads_reg(const char* arg, const char* reg) {
    if (!arg || !reg) return false;
    if (operands_equal(arg, reg)) return true;
    if (arg[0] == '@' && operands_equal(arg + 1, reg)) return true;
    return false;
}

static bool is_indirect_operand(const char* op) {
    if (!op) return false;
    return op[0] == '@';
}

static bool is_local_numeric_label(const char* op) {
    if (!op) return false;
    size_t len = strlen(op);
    if (len < 3 || op[len - 1] != ':') return false;
    if (op[0] != 'L') return false;
    for (size_t i = 1; i + 1 < len; i++) {
        if (op[i] < '0' || op[i] > '9') return false;
    }
    return true;
}

static bool is_compiler_local_label(const char* op) {
    size_t len;

    if (!op) return false;
    len = strlen(op);
    if (len < 2 || op[len - 1] != ':') return false;
    if (op[0] != 'L') return false;
    return true;
}

static bool operand_references_label(const char* arg, const char* label) {
    const char *comma;

    if (!arg || !label) return false;
    while (*arg == ' ' || *arg == '\t') arg++;
    if (strcmp(arg, label) == 0) return true;

    comma = strrchr(arg, ',');
    if (!comma) return false;
    comma++;
    while (*comma == ' ' || *comma == '\t') comma++;
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
    
    // 从列表中移除（不释放内存，因为可能有其他引用）
    ListNode* node = instrs->head;
    ListNode* prev = NULL;
    int i = 0;
    
    while (node && i < index) {
        prev = node;
        node = node->next;
        i++;
    }
    
    if (node) {
        if (prev) {
            prev->next = node->next;
        } else {
            instrs->head = node->next;
        }
        if (node->next) node->next->prev = prev;
        else instrs->tail = prev;
        instrs->len--;
        free(node);
    }
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
    
    // MOV A, x; MOV y, A -> MOV y, x; MOV A, x
    if (operands_equal(dst1, "A") && operands_equal(src2, "A") && 
        is_register_operand(dst2) && (is_register_operand(src1) || is_immediate_operand(src1))) {
        
        // 检查第三条指令是否立即使用A
        bool a_used_next = false;
        if (start + 2 < instrs->len) {
            AsmInstr* ins3 = (AsmInstr*)list_get(instrs, start + 2);
            if (ins3 && !is_mov(ins3)) {
                a_used_next = reg_used_in_instr(ins3, "A");
            }
        }
        
        // 如果A不会立即被使用，优化为 MOV y, x
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
    if (!is_local_numeric_label(ins->op) && !is_compiler_local_label(ins->op)) return 0;

    char label[64];
    size_t len = strlen(ins->op);
    if (len >= sizeof(label)) return 0;
    strncpy(label, ins->op, len - 1);
    label[len - 1] = '\0';

    if (label_is_referenced(instrs, label)) return 0;
    remove_instr(instrs, start);
    return 1;
}

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

/* 窥孔优化：MOV x, A; MOV A, x -> MOV x, A (删除冗余加载) */
static int peephole_redundant_load(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);

    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // 仅对寄存器间的 redundant load 进行删除，避免误删 SFR/内存访问
    if (is_register_operand(dst1) && is_register_operand(src1) &&
        is_register_operand(dst2) && is_register_operand(src2)) {
        // MOV x, A; MOV A, x -> MOV x, A (删除第二条)
        if (operands_equal(src1, "A") && operands_equal(dst2, "A") && 
            operands_equal(dst1, src2)) {
            remove_instr(instrs, start + 1);
            return 1;
        }
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

    // 仅在 src1 不是内存/外设（即为寄存器或立即数）时安全应用
    if (is_memory_operand(src1)) return 0;
    
    // 查找下一条 MOV A, Rx 指令（可能跨越 CLR C 等非破坏性指令）
    int offset = 1;
    while (start + offset < instrs->len && offset <= 2) {
        AsmInstr* ins_next = (AsmInstr*)list_get(instrs, start + offset);
        if (is_basic_block_barrier(ins_next)) break;
        
        if (is_mov(ins_next)) {
            const char* dst_next = get_operand(ins_next, 0);
            const char* src_next = get_operand(ins_next, 1);
            
            // 找到 MOV A, Rx
            if (operands_equal(dst_next, "A") && operands_equal(src_next, dst1)) {
                // 检查 Rx 之后是否还被使用
                if (!reg_read_before_write_or_end(instrs, start + offset + 1, dst1)) {
                    // 修改 MOV A, Rx 为 MOV A, src
                    free(ins_next->args->head->next->elem);
                    ins_next->args->head->next->elem = strdup(src1);
                    
                    // 删除 MOV Rx, src
                    remove_instr(instrs, start);
                    return 1;
                }
            }
            break;  // 遇到其他 MOV，停止查找
        }
        
        // 检查中间指令是否修改了 Rx 或 src
        if (!instr_does_not_modify_reg(ins_next, dst1)) {
            break;
        }
        
        offset++;
    }
    
    return 0;
}

/* 窥孔优化：MOV x, A; MOV y, x -> MOV y, A; MOV x, A */
static int peephole_mov_propagate(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);

    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // MOV Rx, A; MOV Ry, Rx -> MOV Ry, A; MOV Rx, A
    if (is_register_operand(dst1) && operands_equal(src1, "A") && operands_equal(src2, dst1) &&
        is_register_operand(dst2) && !operands_equal(dst2, "A")) {
        
        // 修改第二条指令的源操作数
        free(ins2->args->head->next->elem);
        ins2->args->head->next->elem = strdup("A");
        return 1;
    }
    
    return 0;
}

/* 窥孔优化：MOV mem, A; MOV Rx, mem -> MOV Rx, A; MOV mem, A */
static int peephole_mem_to_reg(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);

    if (is_basic_block_barrier(ins1) || is_basic_block_barrier(ins2)) return 0;
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // MOV mem, A; MOV Rx, mem -> MOV Rx, A; MOV mem, A
    if (operands_equal(src1, "A") && operands_equal(src2, dst1) &&
        dst2 && dst2[0] == 'R' && dst1 && !is_indirect_operand(dst1) && is_memory_operand(dst1)) {
        
        // 交换两条指令：修改第二条为 MOV Rx, A
        free(ins2->args->head->next->elem);
        ins2->args->head->next->elem = strdup("A");
        
        // 交换指令顺序
        ListNode* node1 = instrs->head;
        for (int i = 0; i < start; i++) {
            node1 = node1->next;
        }
        ListNode* node2 = node1->next;
        
        void* temp = node1->elem;
        node1->elem = node2->elem;
        node2->elem = temp;
        
        return 1;
    }
    
    return 0;
}

/* 检查寄存器是否在指令序列中被读取（不包括作为目标） */
static bool reg_read_before_write_or_end(List* instrs, int start, const char* reg) {
    if (!reg || !instrs) return false;
    
    for (int i = start; i < instrs->len; i++) {
        AsmInstr* ins = (AsmInstr*)list_get(instrs, i);
        if (!ins) continue;

        if (is_basic_block_barrier(ins)) {
            if (ins->op && strcmp(ins->op, "RET") == 0) {
                if (operands_equal(reg, "R7") || operands_equal(reg, "R6")) {
                    return true;
                }
                return false;
            }
            return true;
        }
        
        // 检查是否是 RET 指令
        if (ins->op && strcmp(ins->op, "RET") == 0) {
            // 检查是否是返回值寄存器 R7 或 R6
            if (operands_equal(reg, "R7") || operands_equal(reg, "R6")) {
                return true;
            }
            return false;
        }
        
        // 检查该寄存器是否被重新赋值（作为目标）
        if (is_mov(ins)) {
            const char* dst = get_operand(ins, 0);
            if (is_indirect_operand(dst) && operand_reads_reg(dst, reg)) {
                return true;
            }
            if (operands_equal(dst, reg)) {
                return false; // 被重新赋值前没有被读取
            }
        }
        
        // 检查是否被作为源操作数读取
        if (ins->args && ins->args->len > 0) {
            // 第一个参数是目标，从第二个开始检查
            for (int j = (is_mov(ins) ? 1 : 0); j < ins->args->len; j++) {
                const char* arg = (const char*)list_get(ins->args, j);
                if (operand_reads_reg(arg, reg)) {
                    return true; // 被读取了
                }
            }
        }
    }
    
    return false;
}

/* 窥孔优化：删除死代码 - MOV Rx, src 如果 Rx 之后没有被使用 */
static int peephole_dead_code(List* instrs, int start) {
    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    
    if (!is_mov(ins)) return 0;
    
    const char* dst = get_operand(ins, 0);
    
    // 只处理寄存器目标（R0-R7）
    if (!dst || dst[0] != 'R' || dst[1] < '0' || dst[1] > '7') {
        return 0;
    }
    
    // 检查该寄存器在之后是否被读取
    if (!reg_read_before_write_or_end(instrs, start + 1, dst)) {
        remove_instr(instrs, start);
        return 1;
    }
    
    return 0;
}

/* 窥孔优化：SJMP L; L: -> 删除无效跳转 */
static int peephole_sjmp_to_next_label(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;

    AsmInstr* ins = (AsmInstr*)list_get(instrs, start);
    AsmInstr* next = (AsmInstr*)list_get(instrs, start + 1);
    if (!ins || !next || !ins->op || !next->op) return 0;

    if (strcmp(ins->op, "SJMP") != 0) return 0;
    if (!ins->args || ins->args->len < 1) return 0;
    const char* target = (const char*)list_get(ins->args, 0);
    if (!target) return 0;

    size_t len = strlen(next->op);
    if (len == 0 || next->op[len - 1] != ':') return 0;

    char label[64];
    if (len >= sizeof(label)) return 0;
    strncpy(label, next->op, len - 1);
    label[len - 1] = '\0';

    if (strcmp(target, label) == 0) {
        remove_instr(instrs, start);
        return 1;
    }

    return 0;
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

static bool get_next_label_name(AsmInstr* ins, char* label, size_t label_size) {
    size_t len;

    if (!ins || !ins->op || !label || label_size == 0) return false;
    len = strlen(ins->op);
    if (len == 0 || ins->op[len - 1] != ':') return false;
    if (len >= label_size) return false;
    strncpy(label, ins->op, len - 1);
    label[len - 1] = '\0';
    return true;
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
    if (!get_next_label_name(next, label, sizeof(label))) return 0;

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

        if (!next || !next->op) return 0;
        if (!get_next_label_name(next, label, sizeof(label))) return 0;
        if (strcmp(target, label) == 0) {
            remove_instr(instrs, start);
            return 1;
        }
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

        if (!get_next_label_name(label_ins, label, sizeof(label))) continue;
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

/* 对单个section执行窥孔优化 */
static void optimize_section(Section* sec) {
    if (!sec || !sec->asminstrs) return;

    int changed = 1;
    int iterations = 0;
    const int max_iterations = 10;

    while (changed && iterations < max_iterations) {
        changed = 0;
        iterations++;

        for (int i = 0; i < sec->asminstrs->len; i++) {
            int removed = 0;

            removed = peephole_remove_empty_local_label(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_add_zero_16(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_logical_nop(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_drop_dead_mov_before_bit_branch(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_redundant_swap(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            // FIXME: 此优化会错误地删除需要的MOV A, Rx指令
            // 启用更安全的 redundant_load（仅寄存器场景）
            removed = peephole_redundant_load(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            // 启用在 src 非内存时的 temp reg 消除优化
            removed = peephole_eliminate_temp_reg(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mem_to_reg(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_xdata_store_load_forward(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_propagate(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_reg_to_any(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_chain(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            // FIXME: 该规则在当前寄存器分配/调用约定下仍可能误删关键MOV
            // 启用死代码删除（仅寄存器目标，且未被后续读取）
            removed = peephole_dead_code(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_self_mov(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_fold_cond_jump(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_thread_jump_chain(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_jump_to_next_label(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_jump_to_following_label_cluster(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_sjmp_to_next_label(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
        }
    }

    /* XDATA dead-store elimination pass (run AFTER peephole so that
     * store-load-forward has already eliminated redundant loads, making
     * formerly live stores truly dead):
     * Pattern: 6 consecutive instructions:
     *  [0] MOV DPTR, #sym
     *  [1] MOV A, src   (any source: register or immediate)
     *  [2] MOVX @DPTR, A
     *  [3] MOV DPTR, #(sym + 1)
     *  [4] MOV A, src2
     *  [5] MOVX @DPTR, A
     * where sym is not LOADED (no "MOV DPTR,#sym; MOVX A,@DPTR" anywhere in section)
     */
    {
        List* instrs = sec->asminstrs;
        /* Collect all XDATA addresses that are LOADED (MOVX A,@DPTR pattern) */
        char loaded_addrs[64][128];
        int loaded_cnt = 0;
        for (int i = 0; i + 1 < instrs->len && loaded_cnt < 64; i++) {
            AsmInstr* a = (AsmInstr*)list_get(instrs, i);
            AsmInstr* b = (AsmInstr*)list_get(instrs, i + 1);
            if (!a || !b) continue;
            /* MOV DPTR, #addr */
            if (!is_mov(a)) continue;
            const char* dst_a = get_operand(a, 0);
            const char* addr  = get_operand(a, 1);
            if (!dst_a || strcmp(dst_a, "DPTR") != 0) continue;
            if (!addr || addr[0] != '#') continue;
            /* MOVX A, @DPTR  (load) */
            if (!b->op || strcmp(b->op, "MOVX") != 0) continue;
            const char* movx_dst = get_operand(b, 0);
            if (!movx_dst || strcmp(movx_dst, "A") != 0) continue;
            /* Record the base address (strip "+1" suffix for matching) */
            const char* sym_start = addr + 1; /* skip '#' */
            if (*sym_start == '(') sym_start++; /* skip optional '(' */
            const char* sym_end = sym_start;
            while (*sym_end && *sym_end != ' ' && *sym_end != '+' && *sym_end != ')') sym_end++;
            size_t sym_len = sym_end - sym_start;
            if (sym_len == 0 || sym_len >= 128) continue;
            char sym[128];
            strncpy(sym, sym_start, sym_len);
            sym[sym_len] = '\0';
            bool dup = false;
            for (int j = 0; j < loaded_cnt; j++) {
                if (strcmp(loaded_addrs[j], sym) == 0) { dup = true; break; }
            }
            if (!dup) {
                strncpy(loaded_addrs[loaded_cnt], sym, 127);
                loaded_addrs[loaded_cnt][127] = '\0';
                loaded_cnt++;
            }
        }

        int dead_removed = 1;
        while (dead_removed) {
            dead_removed = 0;
            for (int i = 0; i + 5 < instrs->len; i++) {
                AsmInstr* i0 = (AsmInstr*)list_get(instrs, i);
                AsmInstr* i1 = (AsmInstr*)list_get(instrs, i + 1);
                AsmInstr* i2 = (AsmInstr*)list_get(instrs, i + 2);
                AsmInstr* i3 = (AsmInstr*)list_get(instrs, i + 3);
                AsmInstr* i4 = (AsmInstr*)list_get(instrs, i + 4);
                AsmInstr* i5 = (AsmInstr*)list_get(instrs, i + 5);
                if (!i0||!i1||!i2||!i3||!i4||!i5) continue;
                /* [0] MOV DPTR, #sym */
                if (!is_mov(i0)) continue;
                const char* d0 = get_operand(i0, 0);
                const char* a0 = get_operand(i0, 1);
                if (!d0 || strcmp(d0, "DPTR") != 0) continue;
                if (!a0 || a0[0] != '#') continue;
                /* [1] MOV A, <any src> */
                if (!is_mov(i1)) continue;
                const char* d1 = get_operand(i1, 0);
                if (!d1 || strcmp(d1, "A") != 0) continue;
                /* [2] MOVX @DPTR, A */
                if (!i2->op || strcmp(i2->op, "MOVX") != 0) continue;
                const char* d2 = get_operand(i2, 0);
                if (!d2 || strcmp(d2, "@DPTR") != 0) continue;
                /* [3] MOV DPTR, #(sym+1) */
                if (!is_mov(i3)) continue;
                const char* d3 = get_operand(i3, 0);
                if (!d3 || strcmp(d3, "DPTR") != 0) continue;
                /* [4] MOV A, <any src> */
                if (!is_mov(i4)) continue;
                const char* d4 = get_operand(i4, 0);
                if (!d4 || strcmp(d4, "A") != 0) continue;
                /* [5] MOVX @DPTR, A */
                if (!i5->op || strcmp(i5->op, "MOVX") != 0) continue;
                const char* d5 = get_operand(i5, 0);
                if (!d5 || strcmp(d5, "@DPTR") != 0) continue;

                /* Extract symbol name from a0 */
                const char* sym_start2 = a0 + 1;
                if (*sym_start2 == '(') sym_start2++;
                const char* sym_end2 = sym_start2;
                while (*sym_end2 && *sym_end2 != ' ' && *sym_end2 != '+' && *sym_end2 != ')') sym_end2++;
                size_t sym_len2 = sym_end2 - sym_start2;
                if (sym_len2 == 0 || sym_len2 >= 128) continue;
                char sym2[128];
                strncpy(sym2, sym_start2, sym_len2);
                sym2[sym_len2] = '\0';

                /* Skip if this address is ever loaded */
                bool is_loaded = false;
                for (int j = 0; j < loaded_cnt; j++) {
                    if (strcmp(loaded_addrs[j], sym2) == 0) { is_loaded = true; break; }
                }
                if (is_loaded) continue;

                /* Dead store: remove all 6 instructions */
                remove_instr(instrs, i + 5);
                remove_instr(instrs, i + 4);
                remove_instr(instrs, i + 3);
                remove_instr(instrs, i + 2);
                remove_instr(instrs, i + 1);
                remove_instr(instrs, i);
                dead_removed++;
                break;
            }
        }
    }
}

void c51_optimize(C51GenContext* ctx, ObjFile* obj)
{
    (void)ctx;
    (void)obj;
    if (!obj || !obj->sections) return;

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

