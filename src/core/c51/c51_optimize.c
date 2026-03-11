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
        !operands_equal(dst2, "A") && !operands_equal(src1, "A")) {
        
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
    if (operands_equal(dst1, "A") && operands_equal(dst2, src1) && 
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
    if (operands_equal(src1, "A") && operands_equal(src2, dst1) &&
        !operands_equal(dst2, "A")) {
        
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
        dst2 && dst2[0] == 'R' && dst1 && dst1[0] != 'R') {
        
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

            removed = peephole_mov_propagate(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_mov_chain(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            // FIXME: 该规则在当前寄存器分配/调用约定下仍可能误删关键MOV
            // 启用死代码删除（仅寄存器目标，且未被后续读取）
            removed = peephole_dead_code(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }

            removed = peephole_sjmp_to_next_label(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
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

