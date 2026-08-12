/*
 * mcs251.h — MCS-251 standalone interpreter: CPU state + constants.
 *
 * A minimal, dependency-free MCS-251 (Source Mode) emulator.
 * Semantics derived from the QEMU target/mcs251 implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef MCS251_H
#define MCS251_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Constants                                                        */
/* ---------------------------------------------------------------- */

#define MCS251_IRAM_SIZE  0x10000   /* EDATA 00:0000-00:FFFF 64KB (251 架构) */
#define MCS251_CODE_SIZE  0x10000
#define MCS251_XRAM_SIZE  0x10000
#define MCS251_SFR_SIZE   0x80       /* SFR window 0x80-0xFF -> sfr[0..0x7F] */
#define MCS251_RF_SIZE    64
/* STC32G 扩展 SFR (XFR): 经 far 指针 0x7EFA00-0x7EFFFF 访问, 低 16 位
 * = 0xFA00-0xFFFF (DMA 0xFA00 / LIN 0xFDC0 / RTC+I2C+时钟 0xFE00 /
 * PWMA 0xFEC0 / PWMB 0xFEE0)。sim 用 16 位地址窗口 xfr[0x600]。 */
#define MCS251_XFR_LO    0xFA00
#define MCS251_XFR_SIZE  0x600
#define MCS251_EEPROM_SIZE 0x1000    /* IAP/EEPROM 4KB (STC32G12K128) */

/* Register-file special positions */
#define RF_ACC   11
#define RF_B     10
#define RF_DPX   56      /* DR56 = DPL/DPH/DPXL */
#define RF_SPX   60      /* DR60 = SP/SPH */

/* PSW bits */
#define PSW_CY   0x80
#define PSW_AC   0x40
#define PSW_F0   0x20
#define PSW_RS1  0x10
#define PSW_RS0  0x08
#define PSW_OV   0x04
#define PSW_UD   0x02
#define PSW_P    0x01

/* PSW1 bits */
#define PSW1_N   0x20
#define PSW1_Z   0x02

/* STC32G (Keil C251 模式) 中断向量 — 与 STC32G.H 的 *_VECTOR 宏一致:
 * vector = 0x0003 + 8*intno。与标准 8051 表不同 (UART2=0x43, T2=0x63...)。 */
#define VEC_INT0  0x03
#define VEC_T0    0x0B
#define VEC_INT1  0x13
#define VEC_T1    0x1B
#define VEC_SIO   0x23   /* UART1 */
#define VEC_ADC   0x2B
#define VEC_LVD   0x33
#define VEC_SIO2  0x43   /* UART2 */
#define VEC_SPI   0x4B
#define VEC_INT2  0x53
#define VEC_INT3  0x5B
#define VEC_T2    0x63
#define VEC_INT4  0x83
#define VEC_SIO3  0x8B   /* UART3 */
#define VEC_SIO4  0x93   /* UART4 */
#define VEC_T3    0x9B
#define VEC_T4    0xA3
#define VEC_CMP   0xAB
#define VEC_I2C   0xC3
#define VEC_PWMA  0xD3
#define VEC_PWMB  0xDB

/* CMP branch types */
enum {
    CMP_JE = 0, CMP_JNE, CMP_JG, CMP_JLE,
    CMP_JSL, CMP_JSLE, CMP_JSG, CMP_JSGE,
};

/* reg,op2 operations */
enum {
    OP_ADD = 0, OP_SUB, OP_CMP, OP_ORL, OP_ANL, OP_XRL,
    OP_MOV, OP_DIV, OP_MUL, OP_SLL, OP_SRL,
};

/* ---------------------------------------------------------------- */
/* CPU state                                                        */
/* ---------------------------------------------------------------- */
typedef struct {
    uint16_t pc;

    /* Register file (R0-R7 live in iram banks; R8-R15 + WR/DR here). */
    uint8_t rf[MCS251_RF_SIZE];

    /* Internal data RAM (00:0000-00:0FFF); 4 register banks at 0x00-0x1F. */
    uint8_t iram[MCS251_IRAM_SIZE];

    uint8_t psw;
    uint8_t psw1;

    /* Peripheral SFR window: sfr[i] = SFR (0x80 + i).  CPU-core SFRs
     * (ACC/B/SP/SPH/DPL/DPH/DPXL/PSW/PSW1) are aliased to rf[]/psw, not here. */
    uint8_t sfr[MCS251_SFR_SIZE];

    /* Dual data pointers. */
    uint8_t dpl0, dph0, dpl1, dph1, dptr_sel;

    /* Address spaces. */
    uint8_t code[MCS251_CODE_SIZE];
    uint8_t xram[MCS251_XRAM_SIZE];
    uint8_t xfr[MCS251_XFR_SIZE];   /* STC32G XFR 窗口 (0xFA00-0xFFFF) */
    uint8_t eeprom[MCS251_EEPROM_SIZE]; /* IAP/ISP 数据区 */

    /* STC32G SoC 内部状态 (寄存器即状态, 这里只放周期驱动私有量)。 */
    uint32_t wdt_cnt;          /* WDT 倒计时 (WDT_CONTR.EN_WDT 使能时) */
    int      adc_conv_cy;      /* ADC 转换剩余周期; <0 = 空闲 */
    int      spi_cy;           /* SPI 传输剩余周期; <0 = 空闲 */
    uint16_t t_reload[5];      /* T0-T4 自动重装影子值 */
    uint32_t t_sub[5];         /* 定时器预分频子计数 */
    uint8_t  tf2, tf3, tf4;    /* T2/T3/T4 溢出标志 (无 SFR, 内部) */
    uint8_t  i2c_pend;         /* I2C 中断挂起 */
    uint8_t  pwm_pend;         /* bit0=PWMA bit1=PWMB 更新中断挂起 */
    uint16_t pwm_cnt[2];       /* PWMA/PWMB 计数器 (CNTR) */
    uint16_t pwm_pre[2];       /* PWMA/PWMB 预分频子计数 */
    int      dma_m2m_left;     /* DMA M2M 剩余字节; <0 = 空闲 */
    uint16_t dma_m2m_src, dma_m2m_dst, dma_m2m_amt;
    uint32_t rtc_ssec;         /* RTC 1/128 秒计数器 (SSEC) */
    /* 外部 INT2/INT3 脉冲 (--input 激励 / 演示), 计数后触发 */
    int      int2_cycles, int3_cycles;
    /* CMP 比较器 (CMPCR1 0xE6): 使能后模拟输入每 CMP_TOGGLE 周期翻转 */
    uint32_t cmp_sub;         /* 翻转子计数 */
    uint8_t  cmp_out;         /* 当前比较结果 (CMPRES 镜像) */
    /* I2C 硬件 (ENI2C 时写 I2CTXD 触发主模式发送) */
    int      i2c_cy;          /* 传输剩余周期; <0 = 空闲 */
    uint8_t  i2c_busy;        /* 传输进行中 */
    /* LVD 低压检测 (--lvd 注入 / 周期触发) */
    int      lvd_cy;          /* 距下次低压事件周期; <0 = 无 */
    /* UART RX (--input 注入): 队列 1 字节 */
    uint8_t  uart_rx[4];       /* [0]=UART1 [1]=UART2 [2]=UART3 [3]=UART4 */
    uint8_t  uart_rx_pend[4];
    /* ★ SBUF RX 缓冲 (读 0x99/0x9B/0xAD/0xFE): 真实 8051/STC32G 的 SBUF
       读=接收缓冲 (独立于写=发送缓冲)。原实现 RX 注入直接写 sfr[0x99]
       与 TX 共享 → ISR 读 SBUF 得到 TX 字符 (09 双串口 RX1_Buffer[0]
       ='S' 根因)。 */
    uint8_t  uart_rx_sbuf[4];
    /* 中断处理中标志: 8051 中断响应时硬件自动清 EA (屏蔽所有中断),
       RETI 才恢复 — 同一/低优先级中断在 ISR 中绝不重入。sim 缺此机制
       → ISR 未执行完 (未清 RI/TI) 时新中断重入, 同一 RI 处理 2 次
       (09 双串口 RX1_Buffer 多 1 字节根因)。 */
    int      in_isr;
    /* UART TX: TI 延迟置位 (模拟串行发送耗时: 真实硬件在波特率周期后置
     * TI; sim 若立即置 TI 会在阻塞式发送 (while(!TI)/while(B_TX1)) 进入
     * 等待循环前触发中断 → RETI 后重设忙标志 → 死等, 见 03-外中断)。 */
    uint16_t uart_ti_delay[4]; /* TI 置位延迟剩余周期; 0 = 空闲 */
    uint8_t  uart_ti_con[4];   /* 对应 CON sfr 地址 (0x98/0x9A/0xAC/0xFD) */
    uint8_t  uart_ti_bit[4];   /* TI bit 位置 (UART1-4 均为 bit1) */
    uint8_t  uart_ti_irq[4];   /* 发送时 irq_en (ES/ES2/ES3/ES4) */
    /* 端口锁存输出缓冲 (P0-P7 = SFR 0x80/0x90/0xA0/0xB0/0xC0/0xC8/0xE8/0xF8)
     * — 直接读 sfr[] 即可, 无独立缓冲。 */

    /* SoC timing / interrupts. */
    uint64_t cycles;          /* total machine cycles executed */
    int      irq_requested;   /* latched interrupt request (CPU_INTERRUPT_HARD) */
    uint64_t int0_cycles;     /* cycles remaining before INT0 pulse; <0 = done */

    /* Serial output (UART TX goes here; NULL = discard). */
    FILE *serial_out;

    /* Optional opcode execution histogram (op_stats != NULL enables). */
    uint64_t op_stats[256];
    int      op_stats_on;

    /* --- Function-level behavior tracing (P0c: -sym / --trace-sfr) --- */
    struct SymEntry { uint16_t addr; const char *name; } *syms;
    int sym_n;
    int cur_func;             /* 当前执行所在函数索引 (-1 = 无) */
    int last_func_idx;        /* func_of_pc 缓存: 最近命中函数索引 (O(1) 快速路径) */
    struct FuncRec {
        uint16_t entry;
        uint64_t first_cy;
        uint32_t sfr_writes;
        uint32_t calls;
        uint16_t ret_to;
        int      ret_done;    /* ret_to 已记录 (0 也是合法返回地址) */
        int      reached;
    } *func_recs;             /* 与 syms 同尺寸分配 (sym_n 个) */
    /* 逃逸/违规检测 */
    int      escaped;
    uint16_t escape_pc;
    uint16_t escape_src;      /* 逃逸前的最后一条范围内指令 (跳转来源) */
    uint16_t last_pc;         /* 最近一条范围内指令地址 */
    uint64_t code_lo, code_hi; /* 装载的代码有效范围 */
    /* 指令覆盖位图 (每指令 1 bit) */
    uint8_t *cov_map;
    uint64_t cov_lo, cov_hi;
    /* SFR 写日志 */
    struct { uint64_t cy; uint8_t dir8; uint8_t val; } *sfr_trace;
    int sfr_trace_n, sfr_trace_cap;
    /* XFR 写日志 (扩展SFR, 16位地址) */
    struct { uint64_t cy; uint16_t addr; uint8_t val; } *xfr_trace;
    int xfr_trace_n, xfr_trace_cap;
    /* RET 栈一致性: 所有曾被 push 过的返回地址位图 + 违规计数 */
    uint8_t  ret_pushed[0x10000 / 8];
    uint32_t ret_mismatch;   /* RET 目标在代码内但从未 push (真链接 bug) */
    uint32_t restarts;       /* RET 目标在代码外 (Keil main 返回 → 重启, 非违规) */
    uint16_t restart_retval; /* 首次 RESTART 时 WR6 (main 返回值) */
    uint16_t ret_mismatch_pc;  /* 首个未命中 push 的 RET 目标 */
    uint16_t ret_mismatch_src; /* 首个违规 RET 指令自身地址 */
    uint16_t ret_mismatch_sp;  /* 首个违规 RET 时的 SP */
    uint8_t  ret_mismatch_stk[6]; /* 栈顶 6 字节现场 */
    int      hit_cycle_limit;  /* 主循环因 --max-cycles 终止 */
} MCS251;

/* ---------------------------------------------------------------- */
/* Prototypes                                                       */
/* ---------------------------------------------------------------- */

/* main.c */
void mcs251_dump_state(MCS251 *c, FILE *f);
int  mcs251_load_bin(MCS251 *c, const char *path);

/* mem.c */
void  mcs251_reset(MCS251 *c);
uint8_t  mcs251_ld_reg8(MCS251 *c, int m);
void  mcs251_st_reg8(MCS251 *c, int m, uint8_t v);
uint16_t mcs251_ld_wrj16(MCS251 *c, int j);
void  mcs251_st_wrj16(MCS251 *c, int j, uint16_t v);
uint32_t mcs251_ld_drk32(MCS251 *c, int k);
void  mcs251_st_drk32(MCS251 *c, int k, uint32_t v);
uint8_t  mcs251_ld_iram8(MCS251 *c, uint32_t addr);
void  mcs251_st_iram8(MCS251 *c, uint32_t addr, uint8_t v);
uint8_t  mcs251_ld_ri8(MCS251 *c, int i);
void  mcs251_st_ri8(MCS251 *c, int i, uint8_t v);
uint16_t mcs251_ld_iram16(MCS251 *c, uint32_t addr);
void  mcs251_st_iram16(MCS251 *c, uint32_t addr, uint16_t v);
uint32_t mcs251_ld_iram32(MCS251 *c, uint32_t addr);
void  mcs251_st_iram32(MCS251 *c, uint32_t addr, uint32_t v);
uint8_t  mcs251_ld_direct8(MCS251 *c, uint8_t dir8);
void  mcs251_st_direct8(MCS251 *c, uint8_t dir8, uint8_t v);
uint8_t  mcs251_ld_mem8(MCS251 *c, uint32_t addr);
void  mcs251_st_mem8(MCS251 *c, uint32_t addr, uint8_t v);
uint16_t mcs251_ld_mem16(MCS251 *c, uint32_t addr);
void  mcs251_st_mem16(MCS251 *c, uint32_t addr, uint16_t v);
uint32_t mcs251_ld_mem32(MCS251 *c, uint32_t addr);
void  mcs251_st_mem32(MCS251 *c, uint32_t addr, uint32_t v);
uint8_t  mcs251_ld_code8(MCS251 *c, uint32_t addr);
uint8_t  mcs251_ld_xram8(MCS251 *c, uint32_t addr);
void  mcs251_st_xram8(MCS251 *c, uint32_t addr, uint8_t v);
uint16_t mcs251_ld_xram16(MCS251 *c, uint32_t addr);
void  mcs251_st_xram16(MCS251 *c, uint32_t addr, uint16_t v);
uint32_t mcs251_ld_xram32(MCS251 *c, uint32_t addr);
void  mcs251_st_xram32(MCS251 *c, uint32_t addr, uint32_t v);

uint16_t mcs251_ld_dptr(MCS251 *c);
void  mcs251_st_dptr(MCS251 *c, uint16_t v);

/* alu.c — flag helpers */
void mcs251_add8_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t cin, int up);
void mcs251_sub8_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t borrow, int up);
void mcs251_logic8_flags(MCS251 *c, uint32_t res);
void mcs251_shift8_flags(MCS251 *c, uint32_t res, uint32_t carryout);
void mcs251_shiftw_flags(MCS251 *c, uint32_t res, uint32_t carryout);
void mcs251_muldiv8_flags(MCS251 *c, uint32_t ov);
void mcs251_addw_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t cin);
void mcs251_subw_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t borrow);
void mcs251_logicw_flags(MCS251 *c, uint32_t res, uint32_t size);
void mcs251_set_parity(MCS251 *c, uint32_t v);

/* soc.c — SoC peripherals */
void mcs251_arm_timers(MCS251 *c);
void mcs251_timer_tick(MCS251 *c, int which);
void mcs251_uart_send(MCS251 *c);
void mcs251_uart2_send(MCS251 *c);
void mcs251_uart3_send(MCS251 *c);
void mcs251_uart4_send(MCS251 *c);
void mcs251_soc_cycle(MCS251 *c);
int  mcs251_poll_interrupt(MCS251 *c);  /* returns 1 if taken */
int  mcs251_irq_pending(MCS251 *c);     /* 有挂起且使能的中断 (RETI 后重入检查) */
/* STC32G XFR 访问 (经 @DRk/MOVX 远指针路径, 带外设副作用) */
uint8_t mcs251_ld_xfr8(MCS251 *c, uint16_t xa);
uint8_t mcs251_ld_far8(MCS251 *c, uint32_t addr24);
void mcs251_st_far8(MCS251 *c, uint32_t addr24, uint8_t v);
uint16_t mcs251_ld_far16(MCS251 *c, uint32_t addr24);
uint32_t mcs251_ld_far32(MCS251 *c, uint32_t addr24);
void mcs251_st_far16(MCS251 *c, uint32_t addr24, uint16_t v);
void mcs251_st_far32(MCS251 *c, uint32_t addr24, uint32_t v);
void  mcs251_st_xfr8(MCS251 *c, uint16_t xa, uint8_t v);
/* IAP 触发器 (写 IAP_TRIG 0x5A/0xA5 序列) */
void  mcs251_iap_trigger(MCS251 *c);
/* ADC 启动 / SPI 传输启动 (写寄存器的副作用入口) */
void  mcs251_adc_start(MCS251 *c);
void  mcs251_spi_start(MCS251 *c);
/* 定时器 TLx/THx 写 → 更新重装影子 */
void  mcs251_timer_reload_note(MCS251 *c, int which);
/* CMP/I2C 写寄存器副作用入口 (st_xfr8/soc.c 内部调用) */
void  mcs251_cmp_enable(MCS251 *c);
void  mcs251_i2c_start(MCS251 *c);
/* LVD 低压事件注入 (--lvd CLI) */
void  mcs251_lvd_trigger(MCS251 *c);
/* UART RX 注入 (--input) */
void  mcs251_uart_rx_inject(MCS251 *c, int uart_no, uint8_t ch);
/* WDT 复位 (保留 code/符号/输出) */
void  mcs251_reset_keep_io(MCS251 *c);

/* decode.c */
int  mcs251_execute_one(MCS251 *c);   /* fetch + decode + execute; returns cycles */

/* Global instruction-trace flag (set by main.c via `-d in_asm`). */
extern int g_trace_asm;

/* Global opcode histogram flag (set by main.c via `--op-stats`). */
extern int g_op_stats;

/* Global function-trace flag (enabled when `-sym` is provided). */
extern int g_trace_func;

/* Combined trace-feature mask: all off => per-instruction trace overhead skipped. */
extern int g_trace_features;
/* --coverage 启用标记 (并入 g_trace_features, 见 mcs251_update_trace_features). */
extern int g_cov_on;
/* Recompute g_trace_features from the individual trace globals (startup only). */
void  mcs251_update_trace_features(void);

/* Global stack-trace flag (set by main.c via `--trace-stack`). */
extern int g_trace_stack;

/* Global stack-region write trace (set by main.c via `--trace-stkwr`). */
extern int g_trace_stkwr;

/* Software write watchpoint (set by main.c via `--trace-watch ADDR`). */
extern int g_trace_watch;

#endif /* MCS251_H */
