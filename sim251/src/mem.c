/*
 * mem.c — MCS-251 memory & register-file access.
 *
 * Direct addressing: 00-7F -> IRAM, 80-FF -> SFR (CPU-core SFRs are
 * aliased to rf[]/psw).  Indirect (@Ri/@WRj/@DRk) -> data space
 * (internal RAM below 0x1000, otherwise XRAM).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "mcs251.h"

static inline int reg_bank_base(MCS251 *c)
{
    return c->psw & (PSW_RS1 | PSW_RS0);
}

/* ---------------------------------------------------------------- */
/* Register file                                                    */
/* ---------------------------------------------------------------- */

/* 寄存器文件越界防御: 任何 rf[>63] 访问都是解码 bug, 静默越界会写坏
 * 相邻字段 (历史上 sub8 CMP 哨兵 -1→255 越界写 c->rf[255]→iram[0xBF]
 * 破坏栈返回地址)。这里改为报警 + 截断, 不再静默破坏内存。 */
static void rf_oob_warn(const char *fn, int idx, uint64_t cy)
{
    fprintf(stderr, "[MEM] %s: register index %d out of range (>%d) cy=%llu\n",
            fn, idx, MCS251_RF_SIZE - 1, (unsigned long long)cy);
}

uint8_t mcs251_ld_reg8(MCS251 *c, int m)
{
    if (m < 8)
        return c->iram[reg_bank_base(c) + m];
    if (m >= MCS251_RF_SIZE) {
        rf_oob_warn("ld_reg8", m, c->cycles);
        return 0;
    }
    return c->rf[m];
}

void mcs251_st_reg8(MCS251 *c, int m, uint8_t v)
{
    if (m < 8) {
        c->iram[reg_bank_base(c) + m] = v & 0xFF;
    } else if (m < MCS251_RF_SIZE) {
        c->rf[m] = v & 0xFF;
    } else {
        rf_oob_warn("st_reg8", m, c->cycles);
    }
}

/* Word register WRj is BIG-ENDIAN: Rj = high byte, R(j+1) = low byte. */
uint16_t mcs251_ld_wrj16(MCS251 *c, int j)
{
    if (j < 8) {
        int b = reg_bank_base(c) + j;
        return (uint16_t)((c->iram[b] << 8) | c->iram[b + 1]);
    }
    if (j >= MCS251_RF_SIZE) {
        rf_oob_warn("ld_wrj16", j, c->cycles);
        return 0;
    }
    return (uint16_t)((c->rf[j] << 8) | c->rf[j + 1]);
}

void mcs251_st_wrj16(MCS251 *c, int j, uint16_t v)
{
    if (j < 8) {
        int b = reg_bank_base(c) + j;
        c->iram[b]     = (v >> 8) & 0xFF;
        c->iram[b + 1] =  v & 0xFF;
    } else if (j < MCS251_RF_SIZE) {
        c->rf[j]     = (v >> 8) & 0xFF;
        c->rf[j + 1] =  v & 0xFF;
    } else {
        rf_oob_warn("st_wrj16", j, c->cycles);
    }
}

/* Dword register DRk is BIG-ENDIAN: Rk = high byte (80251 硬件语义, 与 WRj
 * 一致 — Keil/TCC 装载 far 地址 WR4=0x007E, WR6=0xFBF1 → DR4=0x007EFBF1,
 * @DR4 低 16 = 0xFBF1 → XFR 窗口。若用小端会得 0xF1FB7E00 → &0xFFFF=0x7E00,
 * far 访问全错位, 外设模型失效)。
 * 例外: DR60 = SPX (SP/SPH) 是 16 位小端字寄存器 — rf[60]=SP(低), rf[61]=SPH(高),
 * `MOV DR60,#data16` 必须把 data16 直接进 SPX (Keil 启动设栈, ?STACK 位置对齐)。 */
uint32_t mcs251_ld_drk32(MCS251 *c, int k)
{
    if (k == RF_SPX)    /* DR60 = SPX: 16 位, R60=SP 低 R61=SPH 高 */
        return (uint32_t)(c->rf[RF_SPX] | (c->rf[RF_SPX + 1] << 8));
    if (k < 8) {
        int b = reg_bank_base(c) + k;
        return (uint32_t)c->iram[b] << 24
             | ((uint32_t)c->iram[b + 1] << 16)
             | ((uint32_t)c->iram[b + 2] << 8)
             | c->iram[b + 3];
    }
    if (k >= MCS251_RF_SIZE) {
        rf_oob_warn("ld_drk32", k, c->cycles);
        return 0;
    }
    return (uint32_t)c->rf[k] << 24
         | ((uint32_t)c->rf[k + 1] << 16)
         | ((uint32_t)c->rf[k + 2] << 8)
         | c->rf[k + 3];
}

void mcs251_st_drk32(MCS251 *c, int k, uint32_t v)
{
    if (k == RF_SPX) {  /* DR60 = SPX: 16 位小端 (SP=rf[60], SPH=rf[61]) */
        c->rf[RF_SPX]     = v & 0xFF;
        c->rf[RF_SPX + 1] = (v >> 8) & 0xFF;
        c->rf[RF_SPX + 2] = 0;
        c->rf[RF_SPX + 3] = 0;
    } else if (k < 8) {
        int b = reg_bank_base(c) + k;
        c->iram[b]     = (v >> 24) & 0xFF;
        c->iram[b + 1] = (v >> 16) & 0xFF;
        c->iram[b + 2] = (v >> 8) & 0xFF;
        c->iram[b + 3] =  v & 0xFF;
    } else if (k < MCS251_RF_SIZE) {
        c->rf[k]     = (v >> 24) & 0xFF;
        c->rf[k + 1] = (v >> 16) & 0xFF;
        c->rf[k + 2] = (v >> 8) & 0xFF;
        c->rf[k + 3] =  v & 0xFF;
    } else {
        rf_oob_warn("st_drk32", k, c->cycles);
    }
}

/* ---------------------------------------------------------------- */
/* @Ri indirect: addr = bank-selected R0/R1 value, data space       */
/* ---------------------------------------------------------------- */

uint8_t mcs251_ld_ri8(MCS251 *c, int i)
{
    return mcs251_ld_iram8(c, mcs251_ld_reg8(c, i));
}

void mcs251_st_ri8(MCS251 *c, int i, uint8_t v)
{
    mcs251_st_iram8(c, mcs251_ld_reg8(c, i), v);
}

/* ---------------------------------------------------------------- */
/* Internal data RAM (dynamic address)                               */
/* ---------------------------------------------------------------- */

uint8_t mcs251_ld_iram8(MCS251 *c, uint32_t addr)
{
    uint8_t v = c->iram[addr & (MCS251_IRAM_SIZE - 1)];
    if (g_trace_stkwr && addr >= 0xBC && addr <= 0x1BB)
        fprintf(stderr, "[STKRD] 0x%04X -> %02X cy=%llu\n",
                (unsigned)addr, v, (unsigned long long)c->cycles);
    return v;
}

void mcs251_st_iram8(MCS251 *c, uint32_t addr, uint8_t v)
{
    if ((addr >= 0x48 && addr <= 0x53) && c->cycles > 3260)
        fprintf(stderr, "[ARRW] pc=%04X 0x%04X <- %02X cy=%llu\n",
                (unsigned)(c->pc), (unsigned)addr, v,
                (unsigned long long)c->cycles);
    if (g_trace_stkwr && addr >= 0xBC && addr <= 0x1BB)
        fprintf(stderr, "[STKWR] 0x%04X <- %02X cy=%llu\n",
                (unsigned)addr, v, (unsigned long long)c->cycles);
    c->iram[addr & (MCS251_IRAM_SIZE - 1)] = v & 0xFF;
}

uint16_t mcs251_ld_iram16(MCS251 *c, uint32_t addr)
{
    addr &= MCS251_IRAM_SIZE - 1;
    uint32_t a1 = (addr + 1) & (MCS251_IRAM_SIZE - 1);
    /* STC32 大端: addr 处 = 高字节 */
    return (uint16_t)((c->iram[addr] << 8) | c->iram[a1]);
}

void mcs251_st_iram16(MCS251 *c, uint32_t addr, uint16_t v)
{
    if ((addr >= 0x48 && addr <= 0x53) && c->cycles > 3260)
        fprintf(stderr, "[ARRW16] pc=%04X 0x%04X <- %04X cy=%llu\n",
                (unsigned)(c->pc), (unsigned)addr, v,
                (unsigned long long)c->cycles);
    if (g_trace_stkwr && addr >= 0xBC && addr <= 0x1BB)
        fprintf(stderr, "[STKWR] 0x%04X <- %04X (16bit) cy=%llu\n",
                (unsigned)addr, v, (unsigned long long)c->cycles);
    addr &= MCS251_IRAM_SIZE - 1;
    uint32_t a1 = (addr + 1) & (MCS251_IRAM_SIZE - 1);
    /* STC32 大端: addr 处 = 高字节 */
    c->iram[addr] = (v >> 8) & 0xFF;
    c->iram[a1]   =  v & 0xFF;
}

uint32_t mcs251_ld_iram32(MCS251 *c, uint32_t addr)
{
    addr &= MCS251_IRAM_SIZE - 1;
    uint32_t m = MCS251_IRAM_SIZE - 1;
    /* STC32 大端: addr 处 = 最高字节 */
    return ((uint32_t)c->iram[addr] << 24)
         | ((uint32_t)c->iram[(addr + 1) & m] << 16)
         | ((uint32_t)c->iram[(addr + 2) & m] << 8)
         |  (uint32_t)c->iram[(addr + 3) & m];
}

void mcs251_st_iram32(MCS251 *c, uint32_t addr, uint32_t v)
{
    if ((addr >= 0x48 && addr <= 0x53) && c->cycles > 3260)
        fprintf(stderr, "[ARRW32] pc=%04X 0x%04X <- %08X cy=%llu\n",
                (unsigned)(c->pc), (unsigned)addr, v,
                (unsigned long long)c->cycles);
    if (g_trace_stkwr && addr >= 0xBC && addr <= 0x1BB)
        fprintf(stderr, "[STKWR] 0x%04X <- %08X (32bit) cy=%llu\n",
                (unsigned)addr, v, (unsigned long long)c->cycles);
    addr &= MCS251_IRAM_SIZE - 1;
    uint32_t m = MCS251_IRAM_SIZE - 1;
    /* STC32 大端: addr 处 = 最高字节 */
    c->iram[addr]            = (v >> 24) & 0xFF;
    c->iram[(addr + 1) & m]  = (v >> 16) & 0xFF;
    c->iram[(addr + 2) & m]  = (v >> 8) & 0xFF;
    c->iram[(addr + 3) & m]  =  v & 0xFF;
}

/* ---------------------------------------------------------------- */
/* Memory-space access (internal < 0x1000, else XRAM)                */
/* ---------------------------------------------------------------- */

uint8_t mcs251_ld_mem8(MCS251 *c, uint32_t addr)
{
    if (addr < MCS251_IRAM_SIZE)
        return mcs251_ld_iram8(c, addr);
    return c->xram[addr & (MCS251_XRAM_SIZE - 1)];
}

void mcs251_st_mem8(MCS251 *c, uint32_t addr, uint8_t v)
{
    if (addr < MCS251_IRAM_SIZE)
        mcs251_st_iram8(c, addr, v);
    else
        c->xram[addr & (MCS251_XRAM_SIZE - 1)] = v & 0xFF;
}

uint16_t mcs251_ld_mem16(MCS251 *c, uint32_t addr)
{
    if (addr < MCS251_IRAM_SIZE)
        return mcs251_ld_iram16(c, addr);
    /* STC32 大端: addr 处 = 高字节 */
    return (uint16_t)((c->xram[addr & (MCS251_XRAM_SIZE - 1)] << 8)
                    | c->xram[(addr + 1) & (MCS251_XRAM_SIZE - 1)]);
}

void mcs251_st_mem16(MCS251 *c, uint32_t addr, uint16_t v)
{
    if (addr < MCS251_IRAM_SIZE) {
        mcs251_st_iram16(c, addr, v);
    } else {
        uint32_t a = addr & (MCS251_XRAM_SIZE - 1);
        /* STC32 大端: addr 处 = 高字节 */
        c->xram[a]            = (v >> 8) & 0xFF;
        c->xram[(a + 1) & (MCS251_XRAM_SIZE - 1)] =  v & 0xFF;
    }
}

uint32_t mcs251_ld_mem32(MCS251 *c, uint32_t addr)
{
    if (addr < MCS251_IRAM_SIZE)
        return mcs251_ld_iram32(c, addr);
    uint32_t a = addr & (MCS251_XRAM_SIZE - 1);
    /* STC32 大端: addr 处 = 最高字节 */
    return ((uint32_t)c->xram[a] << 24)
         | ((uint32_t)c->xram[(a + 1) & (MCS251_XRAM_SIZE - 1)] << 16)
         | ((uint32_t)c->xram[(a + 2) & (MCS251_XRAM_SIZE - 1)] << 8)
         |  (uint32_t)c->xram[(a + 3) & (MCS251_XRAM_SIZE - 1)];
}

void mcs251_st_mem32(MCS251 *c, uint32_t addr, uint32_t v)
{
    if (addr < MCS251_IRAM_SIZE) {
        mcs251_st_iram32(c, addr, v);
    } else {
        uint32_t a = addr & (MCS251_XRAM_SIZE - 1);
        /* STC32 大端: addr 处 = 最高字节 */
        c->xram[a]            = (v >> 24) & 0xFF;
        c->xram[(a + 1) & (MCS251_XRAM_SIZE - 1)] = (v >> 16) & 0xFF;
        c->xram[(a + 2) & (MCS251_XRAM_SIZE - 1)] = (v >> 8) & 0xFF;
        c->xram[(a + 3) & (MCS251_XRAM_SIZE - 1)] =  v & 0xFF;
    }
}

/* ---------------------------------------------------------------- */
/* Code / XRAM raw access                                            */
/* ---------------------------------------------------------------- */

uint8_t mcs251_ld_code8(MCS251 *c, uint32_t addr)
{
    return c->code[addr & (MCS251_CODE_SIZE - 1)];
}

uint8_t mcs251_ld_xram8(MCS251 *c, uint32_t addr)
{
    if (addr >= MCS251_XFR_LO && addr < 0x10000)
        return mcs251_ld_xfr8(c, (uint16_t)addr);
    return c->xram[addr & (MCS251_XRAM_SIZE - 1)];
}

void mcs251_st_xram8(MCS251 *c, uint32_t addr, uint8_t v)
{
    if (addr >= MCS251_XFR_LO && addr < 0x10000) {
        mcs251_st_xfr8(c, (uint16_t)addr, v);
        return;
    }
    c->xram[addr & (MCS251_XRAM_SIZE - 1)] = v & 0xFF;
}

/* 16/32 位 xram 访问: 逐字节路由 (低 16 位地址 0xFA00-0xFFFF → XFR 窗口)。
 * 用于 @DRk 间接访问 (far 指针), 与 8 位 xram8 语义一致。 */
uint16_t mcs251_ld_xram16(MCS251 *c, uint32_t addr)
{
    /* STC32 大端: addr 处 = 高字节 */
    return (uint16_t)(((uint16_t)mcs251_ld_xram8(c, addr) << 8)
                    | mcs251_ld_xram8(c, addr + 1));
}

void mcs251_st_xram16(MCS251 *c, uint32_t addr, uint16_t v)
{
    /* STC32 大端: addr 处 = 高字节 */
    mcs251_st_xram8(c, addr, (v >> 8) & 0xFF);
    mcs251_st_xram8(c, addr + 1, v & 0xFF);
}

uint32_t mcs251_ld_xram32(MCS251 *c, uint32_t addr)
{
    /* STC32 大端: addr 处 = 最高字节 */
    return ((uint32_t)mcs251_ld_xram8(c, addr) << 24)
         | ((uint32_t)mcs251_ld_xram8(c, addr + 1) << 16)
         | ((uint32_t)mcs251_ld_xram8(c, addr + 2) << 8)
         |  (uint32_t)mcs251_ld_xram8(c, addr + 3);
}

void mcs251_st_xram32(MCS251 *c, uint32_t addr, uint32_t v)
{
    /* STC32 大端: addr 处 = 最高字节 */
    mcs251_st_xram8(c, addr, (v >> 24) & 0xFF);
    mcs251_st_xram8(c, addr + 1, (v >> 16) & 0xFF);
    mcs251_st_xram8(c, addr + 2, (v >> 8) & 0xFF);
    mcs251_st_xram8(c, addr + 3, v & 0xFF);
}

/* ---------------------------------------------------------------- */
/* @DRk 24 位地址路由 (far 指针访问)                                  */
/* 低 24 位地址按高字节路由: 0xFFxxxx → code 区; 其余 → XRAM/XFR       */
/* (低 16 位 0xFA00-0xFFFF 窗口由 mcs251_ld/st_xram8 内部处理)。      */
/* 关键: STC32G 字符串常量放 code (0xFF0000+), PrintString 用 @DRk 读。*/
/* ---------------------------------------------------------------- */

uint8_t mcs251_ld_far8(MCS251 *c, uint32_t addr24)
{
    if ((addr24 & 0xFF0000) == 0xFF0000)      /* code 区 */
        return mcs251_ld_code8(c, addr24 & 0xFFFF);
    /* ★ 非 code: 低 16 位 < 0x10000 是 edata/IRAM (STC32 大端, 全局
       .edata 从 0x08 起) — 与 mcs251_ld_mem8 同路由. 否则 @DRk 读
       指针指向的 edata 全局 (p=g_arr, @DR4=8) 落到 xram 空区, 读到
       0 (suite 48 p[0]). 0xFA00-0xFFFF 窗口由 xram8 内部处理. */
    if ((addr24 & 0xFFFF) < MCS251_IRAM_SIZE)
        return mcs251_ld_iram8(c, addr24 & 0xFFFF);
    return mcs251_ld_xram8(c, addr24 & 0xFFFF);
}

void mcs251_st_far8(MCS251 *c, uint32_t addr24, uint8_t v)
{
    if ((addr24 & 0xFF0000) == 0xFF0000)
        return;                                /* code 只读, 忽略写 */
    if ((addr24 & 0xFFFF) < MCS251_IRAM_SIZE)
        mcs251_st_iram8(c, addr24 & 0xFFFF, v);
    else
        mcs251_st_xram8(c, addr24 & 0xFFFF, v);
}

uint16_t mcs251_ld_far16(MCS251 *c, uint32_t addr24)
{
    /* STC32 大端: addr24 处 = 高字节 */
    return (uint16_t)(((uint16_t)mcs251_ld_far8(c, addr24) << 8)
                    | mcs251_ld_far8(c, addr24 + 1));
}

uint32_t mcs251_ld_far32(MCS251 *c, uint32_t addr24)
{
    /* STC32 大端: addr24 处 = 最高字节 */
    return ((uint32_t)mcs251_ld_far8(c, addr24) << 24)
         | ((uint32_t)mcs251_ld_far8(c, addr24 + 1) << 16)
         | ((uint32_t)mcs251_ld_far8(c, addr24 + 2) << 8)
         |  (uint32_t)mcs251_ld_far8(c, addr24 + 3);
}

void mcs251_st_far16(MCS251 *c, uint32_t addr24, uint16_t v)
{
    /* STC32 大端: addr24 处 = 高字节 */
    mcs251_st_far8(c, addr24, (v >> 8) & 0xFF);
    mcs251_st_far8(c, addr24 + 1, v & 0xFF);
}

void mcs251_st_far32(MCS251 *c, uint32_t addr24, uint32_t v)
{
    /* STC32 大端: addr24 处 = 最高字节 */
    mcs251_st_far8(c, addr24, (v >> 24) & 0xFF);
    mcs251_st_far8(c, addr24 + 1, (v >> 16) & 0xFF);
    mcs251_st_far8(c, addr24 + 2, (v >> 8) & 0xFF);
    mcs251_st_far8(c, addr24 + 3, v & 0xFF);
}

/* ---------------------------------------------------------------- */
/* Direct addressing (00-7F -> IRAM, 80-FF -> SFR)                   */
/* ---------------------------------------------------------------- */

/* CPU-core SFRs stored in rf[]/psw (not in c->sfr[]). */
static uint8_t *sfr_byte_ref(MCS251 *c, uint8_t dir8)
{
    switch (dir8) {
    case 0x81: return &c->rf[RF_SPX + 0];   /* SP   */
    case 0xBD: return &c->rf[RF_SPX + 1];   /* SPH  */
    case 0x82: return &c->rf[RF_DPX + 0];   /* DPL  */
    case 0x83: return &c->rf[RF_DPX + 1];   /* DPH  */
    case 0x84: return &c->rf[RF_DPX + 2];   /* DPXL */
    case 0xD0: return &c->psw;
    case 0xD1: return &c->psw1;
    case 0xE0: return &c->rf[RF_ACC];
    case 0xF0: return &c->rf[RF_B];
    default:   return &c->sfr[dir8 - 0x80];
    }
}

uint8_t mcs251_ld_direct8(MCS251 *c, uint8_t dir8)
{
    if (dir8 < 0x80)
        return c->iram[dir8];
    /* SPSTAT (0xCD): 读清零 SPIF/WCOL (STC32G 硬件行为)。
       必须先返回当前值再清零 — 若先清后返回, 读到的 SPIF 恒 0,
       导致 Keil REF 的 SPI 等待循环 (0x13DE 等 SPIF) 死循环
       (REF 20.1 输出 270B 后卡死)。 */
    if (dir8 == 0xCD && c->spi_cy < 0) {
        uint8_t v = c->sfr[0xCD - 0x80];
        c->sfr[0xCD - 0x80] &= ~0xC0;
        return v;
    }
    if (dir8 == 0xCD) {
        return c->sfr[0xCD - 0x80];
    }
    /* ★ SBUF 读 = RX 接收缓冲 (真实 8051 读写分离; 写 0x99 是 TX 发送
       缓冲, 若读同一数组会得到 TX 字符 — 09 双串口 RX 收到 'S' 根因) */
    if (dir8 == 0x99) return c->uart_rx_sbuf[0];
    if (dir8 == 0x9B) return c->uart_rx_sbuf[1];
    if (dir8 == 0xAD) return c->uart_rx_sbuf[2];
    if (dir8 == 0xFE) return c->uart_rx_sbuf[3];
    return *sfr_byte_ref(c, dir8);
}

/* Write side effects: DPS selection, DPL/DPH sync, SBUF (UART),
 * TCON (timers). */
void mcs251_st_direct8(MCS251 *c, uint8_t dir8, uint8_t v)
{
    if (dir8 < 0x80) {
        c->iram[dir8] = v & 0xFF;
        return;
    }
    /* SFR 写日志 (--trace-sfr): 记录 (cy, addr, val) 事件序列 */
    if (c->sfr_trace) {
        if (c->sfr_trace_n < c->sfr_trace_cap) {
            c->sfr_trace[c->sfr_trace_n].cy = c->cycles;
            c->sfr_trace[c->sfr_trace_n].dir8 = dir8;
            c->sfr_trace[c->sfr_trace_n].val = v & 0xFF;
            c->sfr_trace_n++;
        }
    }
#ifdef MCS251_DEBUG_SPI
    if (dir8 == 0xCF || dir8 == 0xCE || dir8 == 0xCD)
        fprintf(stderr, "[SFR-WR] %02X <- %02X @cy=%lld\n", dir8, v & 0xFF,
                (long long)c->cycles);
#endif
    /* 函数级 SFR 写计数 (依赖 -sym) */
    if (g_trace_func && c->cur_func >= 0 && c->cur_func < c->sym_n)
        c->func_recs[c->cur_func].sfr_writes++;
    *sfr_byte_ref(c, dir8) = v & 0xFF;
    switch (dir8) {
    case 0x86:  /* DPS */
        c->dptr_sel = v & 1;
        break;
    case 0x82:  /* DPL: sync active DPTR low byte */
        if (c->dptr_sel & 1)
            c->dpl1 = v & 0xFF;
        else
            c->dpl0 = v & 0xFF;
        break;
    case 0x83:  /* DPH: sync active DPTR high byte */
        if (c->dptr_sel & 1)
            c->dph1 = v & 0xFF;
        else
            c->dph0 = v & 0xFF;
        break;
    case 0x99:  /* SBUF -> UART1 TX */
        mcs251_uart_send(c);
        break;
    case 0x98:  /* S1CON: TI1 置位请求 UART1 中断 (真实硬件 SETB TI 触发) */
        if (v & 0x02)
            c->irq_requested = 1;
        break;
    case 0x9A:  /* S2CON: TI2 置位请求 UART2 中断 */
        if (v & 0x02)
            c->irq_requested = 1;
        break;
    case 0xAC:  /* S3CON: TI3 置位请求 UART3 中断 */
        if (v & 0x02)
            c->irq_requested = 1;
        break;
    case 0xFD:  /* S4CON: TI4 置位请求 UART4 中断 */
        if (v & 0x02)
            c->irq_requested = 1;
        break;
    case 0x9B:  /* S2BUF -> UART2 TX */
        mcs251_uart2_send(c);
        break;
    case 0xAD:  /* S3BUF -> UART3 TX */
        mcs251_uart3_send(c);
        break;
    case 0xFE:  /* S4BUF -> UART4 TX */
        mcs251_uart4_send(c);
        break;
    case 0x88:  /* TCON -> timers */
        mcs251_arm_timers(c);
        break;
    case 0x8A: case 0x8C:  /* TL0/TH0 */
        mcs251_timer_reload_note(c, 0);
        break;
    case 0x8B: case 0x8D:  /* TL1/TH1 */
        mcs251_timer_reload_note(c, 1);
        break;
    case 0xD7: case 0xD6:  /* T2L/T2H */
        mcs251_timer_reload_note(c, 2);
        break;
    case 0xD5: case 0xD4:  /* T3L/T3H */
        mcs251_timer_reload_note(c, 3);
        break;
    case 0xD3: case 0xD2:  /* T4L/T4H */
        mcs251_timer_reload_note(c, 4);
        break;
    case 0x8E:  /* AUXR (T2R) */
    case 0xDD:  /* T4T3M (T3R/T4R) */
        mcs251_arm_timers(c);
        break;
    case 0xC1:  /* WDT_CONTR: 写入立即重载/清零 */
        if (v & 0x10)   /* CLR_WDT */
            c->wdt_cnt = 0;
        else if (v & 0x20)  /* EN_WDT */
            c->wdt_cnt = 0;
        break;
    case 0xBC:  /* ADC_CONTR: ADC_START 启动转换 */
        if (v & 0x40)
            mcs251_adc_start(c);
        break;
    case 0xE6:  /* CMPCR1: CMPEN 使能/复位翻转子计数 */
        mcs251_cmp_enable(c);
        break;
    case 0xCF:  /* SPDAT: 写启动 SPI 传输 */
#ifdef MCS251_DEBUG_SPI
        fprintf(stderr, "[SPI-WR] v=%02X SPEN=%d SPCTL=%02X\n", v,
                (int)((c->sfr[0xCE - 0x80] & 0x40)!=0), c->sfr[0xCE - 0x80]);
#endif
        if ((c->sfr[0xCE - 0x80] & 0x40))   /* SPEN */
            mcs251_spi_start(c);
        break;
    case 0xC6:  /* IAP_TRIG */
        mcs251_iap_trigger(c);
        break;
    case 0xCD:  /* SPSTAT 写 (清 SPIF/WCOL) */
        c->sfr[0xCD - 0x80] &= ~(v & 0xC0);
        break;
    default:
        break;
    }
}

/* ---------------------------------------------------------------- */
/* Data pointer (dual)                                               */
/* ---------------------------------------------------------------- */

uint16_t mcs251_ld_dptr(MCS251 *c)
{
    if (c->dptr_sel & 1)
        return (uint16_t)((c->dph1 << 8) | c->dpl1);
    return (uint16_t)((c->dph0 << 8) | c->dpl0);
}

void mcs251_st_dptr(MCS251 *c, uint16_t v)
{
    if (c->dptr_sel & 1) {
        c->dpl1 =  v & 0xFF;
        c->dph1 = (v >> 8) & 0xFF;
    } else {
        c->dpl0 =  v & 0xFF;
        c->dph0 = (v >> 8) & 0xFF;
    }
    /* Keep DPX register file in sync for direct reads. */
    c->rf[RF_DPX + 0] =  v & 0xFF;
    c->rf[RF_DPX + 1] = (v >> 8) & 0xFF;
}

/* ---------------------------------------------------------------- */
/* Reset                                                            */
/* ---------------------------------------------------------------- */

void mcs251_reset(MCS251 *c)
{
    memset(c, 0, sizeof(*c));
    c->pc = 0;
    c->cur_func = -1;   /* 尚未进入任何符号函数 */
    c->last_func_idx = -1;  /* func_of_pc 缓存冷启动 */
    /* Stack pointer initial value: 0x0007 per MCS-51 convention. */
    c->rf[RF_SPX + 0] = 0x07;   /* SP  = 0x07 */
    c->rf[RF_SPX + 1] = 0x00;   /* SPH = 0x00 */
    /* 外设空闲 */
    c->adc_conv_cy = -1;
    c->spi_cy = -1;
    c->dma_m2m_left = -1;
    c->i2c_cy = -1;
    c->lvd_cy = -1;
    /* INT0 pulse scheduled ~1000 machine cycles after boot (1ms @1MHz). */
    c->int0_cycles = 1000;
    /* STC32G 复位默认: P0-P7 高电平 (端口上拉). 部分 demo 依赖端口
     * 初值 (如 P3=0xFF 表示按键未按下)。 */
    for (int i = 0; i < 8; i++) {
        uint8_t port = (uint8_t[]){0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xC8, 0xE8, 0xF8}[i];
        mcs251_st_direct8(c, port, 0xFF);
    }
    /* XFR 复位值: RTC 使能后从 0 起; 其余外设寄存器 0。 */
}

void mcs251_reset_keep_io(MCS251 *c)
{
    /* 仅复位 CPU/外设状态, 保留 code/符号表/追踪缓冲 (WDT 复位路径用)。 */
    uint8_t code[MCS251_CODE_SIZE];
    MCS251 saved = *c;
    memcpy(code, c->code, sizeof code);
    memset(c, 0, sizeof(*c));
    c->pc = 0;
    c->cur_func = -1;
    c->last_func_idx = -1;
    memcpy(c->code, code, sizeof code);
    c->syms = saved.syms; c->sym_n = saved.sym_n;
    c->func_recs = saved.func_recs;
    c->serial_out = saved.serial_out;
    c->sfr_trace = saved.sfr_trace; c->sfr_trace_n = saved.sfr_trace_n;
    c->sfr_trace_cap = saved.sfr_trace_cap;
    c->cov_map = saved.cov_map;
    memset(c->ret_pushed, 0, sizeof c->ret_pushed);
    c->rf[RF_SPX + 0] = 0x07;
    c->rf[RF_SPX + 1] = 0x00;
    c->adc_conv_cy = -1;
    c->spi_cy = -1;
    c->dma_m2m_left = -1;
    c->i2c_cy = -1;
    c->lvd_cy = -1;
    c->wdt_cnt = 0;
    c->rtc_ssec = 0;
    c->cycles = saved.cycles;   /* WDT 复位不重置总周期计数 */
    c->hit_cycle_limit = saved.hit_cycle_limit;
    c->escaped = saved.escaped;
    c->code_lo = saved.code_lo; c->code_hi = saved.code_hi;
    c->int0_cycles = 1000;
    for (int i = 0; i < 8; i++) {
        uint8_t port = (uint8_t[]){0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xC8, 0xE8, 0xF8}[i];
        mcs251_st_direct8(c, port, 0xFF);
    }
}
