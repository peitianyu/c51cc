#ifndef C51_REGALLOC_H
#define C51_REGALLOC_H

#include "c51_isel.h"

/* 寄存器约定声明（在 c51_regalloc.c 中定义） */
extern const int param_regs_char[];
extern const int param_regs_int_h[];
extern const int param_regs_int_l[];

/* ============================================================
 * 线性扫描寄存器分配数据结构
 * ============================================================ */

/* 活跃区间结构体 */
typedef struct {
    ValueName val;          /* SSA值编号 */
    int start;              /* 活跃区间开始（定义指令序号） */
    int end;                /* 活跃区间结束（最后使用指令序号） */
    int size;               /* 值的大小（字节数） */
    int reg;                /* 分配的寄存器（-1=未分配，-2=在A中，>=0=寄存器号） */
    int spill_slot;         /* 溢出位置（暂时保留） */
    bool is_param;          /* 是否为参数值 */
} LiveInterval;

/* 线性扫描分配器上下文 */
typedef struct {
    LiveInterval* intervals;    /* 所有活跃区间数组 */
    int interval_count;         /* 活跃区间数量 */
    int interval_capacity;      /* 数组容量 */
    
    /* 活跃寄存器跟踪 */
    int active_regs[3];         /* R0, R1, R2 当前分配的值 */
    int active_reg_end[3];      /* R0, R1, R2 中值的结束位置 */
    
    /* 位置信息 */
    int instr_idx;              /* 当前正在处理的指令序号 */
    
    /* 临时数据 */
    int* sorted_intervals;      /* 按start排序的区间索引数组 */
} LinearScanContext;

/* 初始化线性扫描分配器 */
LinearScanContext* linscan_create(void);

/* 销毁线性扫描分配器 */
void linscan_destroy(LinearScanContext* lsc);

/* 为函数的所有指令计算活跃区间 */
void linscan_compute_intervals(LinearScanContext* lsc, Func* func, C51GenContext* genctx);

/* 执行线性扫描寄存器分配 */
void linscan_allocate(LinearScanContext* lsc, C51GenContext* genctx);

/* 为值分配寄存器（返回分配的基寄存器号） */
int alloc_reg_for_value(ISelContext* isel, ValueName val, int size);

/* 为函数参数分配寄存器 */
void alloc_param_regs(ISelContext* isel, Func* f);

#endif
