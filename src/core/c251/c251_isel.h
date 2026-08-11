#ifndef C251_ISEL_H
#define C251_ISEL_H

#include "c251_gen.h"

/* 指令选择上下文（M2：块指令视图 + 寄存器占用表，支持死值释放/溢出） */
typedef struct ISelContext {
    C251GenContext* ctx;
    Section* sec;
    int label_counter;
    int next_wr;            /* 下一个可分配 WR 索引: 0/2/4/6 */

    /* 寄存器占用表：reg_val[w/2] = 占用 WRw 的值名，-1 空闲（w = 0/2/4/6） */
    int reg_val[4];

    /* 当前块的指令数组视图（isel_block 构建，isel_instr 内只读） */
    Instr** block_instrs;
    int block_instr_count;
    int block_instr_pos;    /* 当前指令在数组中的位置 */

    /* 跨块活值集合（isel_function 预扫描）：value -> int* (块计数)；>=2 块或 PHI 参数 → 永不释放 */
    Dict* global_live;

    /* 当前块 id（phi 拷贝需要知道来源块） */
    int current_block_id;

    /* 块 id → Block* 映射（phi 拷贝查找目标块，isel_function 建立） */
    Dict* block_map;
} ISelContext;

/* 指令选择主入口 */
void isel_function(C251GenContext* ctx, Func* func);
void isel_block(ISelContext* isel, Block* block);
void isel_instr(ISelContext* isel, Instr* ins, Instr* next);

/* 发射汇编指令 */
void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2);

/* 值 → 寄存器分配：空闲优先 → 块内死值释放 → 返回 -1（调用方走溢出路径） */
int isel_alloc_wr(ISelContext* isel, ValueName val);
int isel_value_reg(C251GenContext* ctx, ValueName val);

#endif
