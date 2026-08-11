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

    /* Keil C251 ABI 参数寄存器分配状态（每函数重置）：
     * 被调函数侧: isel_function 预计算全部参数的 ABI 寄存器表（param_abi_*），
     *   PARAM 指令按声明序查表消费；物化目标避开其他参数的 ABI 槽（防覆写）。
     * 调用方侧: 实参装载用 abi_param_reg 计算目标寄存器（每次 CALL 重置）。 */
    int param_counter;      /* 被调函数已消费的参数个数 */
    int param_used[16];     /* 字节寄存器占用位图 (0-15) */
    int param_u8i;          /* u8 候选序列游标 {11,7,6,5,4} */
    int param_u16i;         /* u16 候选序列游标 {6,4,2,0} */
    /* 参数 ABI 预计算表（isel_function 建立；PARAM 查表消费，避免重复分配） */
    int param_abi_reg[16];  /* 参数 i → ABI 寄存器 (u8: 字节号 / u16: WR 索引), -2 宽度不支持, -1 不足 */
    int param_abi_sz[16];   /* 参数 i → 宽度 (1/2) */
    int param_abi_count;    /* 参数总数 */
    int param_abi_bytes[32]; /* 全部参数 ABI 字节槽集（物化冲突检查用） */
    int param_abi_nbytes;   /* param_abi_bytes 长度 */

    /* BR 免物化 hint（比较指令 → BR 直接复用 CMP 标志，跳过 0/1 物化）：
     * 比较指令处理时前瞻（可选 NE X,0 后）发现结果仅被 BR 使用 → 只发 CMP，
     * 记录 br_hint_jump（结果为真时的条件跳转）；BR 命中时直接跳转。
     * br_hint_ne_skip = 模式中被消费的 NE 指令 dest（NE 处理时跳过），-1 = 无。 */
    int br_hint_cond;        /* 免物化比较结果值名, -1 = 无 */
    char br_hint_jump[8];    /* 结果为真时的条件跳转助记符 (如 "JE"/"JSL") */
    int br_hint_ne_skip;     /* 被消费的 NE 指令 dest 值名, -1 = 无 */
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
