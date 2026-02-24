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
        instrs->len--;
        free(node);
    }
}

/* 窥孔优化：MOV A, x; MOV y, A -> MOV y, x (如果之后不立即使用A) */
static int peephole_mov_chain(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    
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
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // MOV x, A; MOV A, x -> MOV x, A (删除第二条)
    if (operands_equal(src1, "A") && operands_equal(dst2, "A") && 
        operands_equal(dst1, src2)) {
        remove_instr(instrs, start + 1);
        return 1;
    }
    
    return 0;
}

/* 窥孔优化：MOV A, x; MOV x, A -> 删除两条（如果x之后不使用） */
static int peephole_redundant_swap(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    
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

/* 窥孔优化：MOV Rx, src; MOV A, Rx -> MOV A, src (如果 Rx 之后不再使用) */
static int peephole_eliminate_temp_reg(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    
    if (!is_mov(ins1) || !is_mov(ins2)) return 0;
    
    const char* dst1 = get_operand(ins1, 0);
    const char* src1 = get_operand(ins1, 1);
    const char* dst2 = get_operand(ins2, 0);
    const char* src2 = get_operand(ins2, 1);
    
    // MOV Rx, src; MOV A, Rx -> MOV A, src
    if (dst1 && dst1[0] == 'R' && 
        operands_equal(dst2, "A") && 
        operands_equal(src2, dst1) &&
        !operands_equal(src1, "A")) {
        
        // 检查 Rx 之后是否还被使用
        if (!reg_read_before_write_or_end(instrs, start + 2, dst1)) {
            // 修改第二条指令的源操作数为第一条的源
            free(ins2->args->head->next->elem);
            ins2->args->head->next->elem = strdup(src1);
            
            // 删除第一条指令
            remove_instr(instrs, start);
            return 1;
        }
    }
    
    return 0;
}

/* 窥孔优化：MOV x, A; MOV y, x -> MOV y, A; MOV x, A */
static int peephole_mov_propagate(List* instrs, int start) {
    if (start + 1 >= instrs->len) return 0;
    
    AsmInstr* ins1 = (AsmInstr*)list_get(instrs, start);
    AsmInstr* ins2 = (AsmInstr*)list_get(instrs, start + 1);
    
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
                if (operands_equal(arg, reg)) {
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
            
            // 尝试各种优化模式
            removed = peephole_redundant_swap(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
            
            removed = peephole_redundant_load(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
            
            removed = peephole_eliminate_temp_reg(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
            
            removed = peephole_mem_to_reg(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
            
            removed = peephole_mov_propagate(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
            
            removed = peephole_mov_chain(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
            
            // 死代码消除放在最后
            removed = peephole_dead_code(sec->asminstrs, i);
            if (removed) { changed = 1; continue; }
        }
    }
}

void c51_optimize(C51GenContext* ctx, ObjFile* obj)
{
    if (!obj || !obj->sections) return;
    
    // 对每个代码段执行窥孔优化
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section* sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) {
            optimize_section(sec);
        }
    }
}