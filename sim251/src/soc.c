/*
 * soc.c — STC32G SoC peripherals: timers T0-T4, UART1-4, WDT, ADC, SPI,
 *         I2C, RTC, CMP, PWM, DMA + 中断控制器.
 *
 * 注册级行为模型 (非 RTL, 见 docs/sim-keil-validation-design.md §14):
 *   每个外设 = SFR/XFR 寄存器组 + 周期驱动行为 + 中断产生。
 *   寄存器即状态; 只建模程序可观测行为。
 *
 * 时钟: sim 每机器周期 = 1 条指令。定时器 1T 模式每周期计数一次,
 * 12T 模式每 12 周期一次, 预分频 (PS+1)。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "mcs251.h"

/* --input 注入缓冲 (main.c) */
extern uint8_t *g_rx_buf;
extern size_t g_rx_n, g_rx_i;
extern uint64_t g_rx_last_cy;

/* ------------------------------------------------------------------ */
/* SFR 位定义 (STC32G.H 校验)                                          */
/* ------------------------------------------------------------------ */

/* TCON 0x88 */
#define TCON_IT0  0x01
#define TCON_IE0  0x01   /* 与 IT0 同 bit (位寻址) */
#define TCON_IT1  0x02
#define TCON_IE1  0x04
#define TCON_TR0  0x10
#define TCON_TF0  0x20
#define TCON_TR1  0x40
#define TCON_TF1  0x80

/* IE 0xA8 */
#define IE_EA     0x80
#define IE_ELVD   0x40
#define IE_EADC   0x20
#define IE_ES     0x10
#define IE_ET1    0x08
#define IE_EX1    0x04
#define IE_ET0    0x02
#define IE_EX0    0x01

/* IE2 0xAF */
#define IE2_ES2   0x01
#define IE2_ESPI  0x02
#define IE2_ET2   0x04
#define IE2_ES3   0x08
#define IE2_ES4   0x10
#define IE2_ET3   0x20
#define IE2_ET4   0x40
#define IE2_EUSB  0x80

/* INTCLKO 0x8F: EX2=4 EX3=5 EX4=6 */
#define INTCLKO_EX2  0x10
#define INTCLKO_EX3  0x20
#define INTCLKO_EX4  0x40

/* AUXINTIF 0xEF: LVDIF=0 INT2IF=4 INT3IF=5 INT4IF=6 */
#define AUXINTIF_LVDIF  0x01
#define AUXINTIF_INT2IF 0x10
#define AUXINTIF_INT3IF 0x20
#define AUXINTIF_INT4IF 0x40

/* AUXR 0x8E */
#define AUXR_T0x12  0x80
#define AUXR_T1x12  0x40
#define AUXR_T2R    0x10
#define AUXR_T2x12  0x04

/* T4T3M 0xDD */
#define T4T3M_T4R   0x80
#define T4T3M_T4x12 0x20
#define T4T3M_T3R   0x08
#define T4T3M_T3x12 0x02

/* WDT_CONTR 0xC1 */
#define WDT_EN_WDT    0x20
#define WDT_CLR_WDT   0x10
#define WDT_IDL_WDT   0x08
#define WDT_PS_MASK   0x07

/* ADC_CONTR 0xBC */
#define ADC_POWER  0x80
#define ADC_START  0x40
#define ADC_FLAG   0x20
#define ADC_CHS    0x0F

/* SPSTAT 0xCD / SPCTL 0xCE */
#define SPIF  0x80
#define WCOL  0x40
#define SPEN  0x40

/* CMPCR1 0xE6 */
#define CMP_CMPEN  0x80
#define CMP_CMPIF  0x40
#define CMP_PIE    0x20
#define CMP_NIE    0x10
#define CMP_CMPRES 0x08

/* IAP 命令 */
#define IAP_CMD_READ  1
#define IAP_CMD_PROG  2
#define IAP_CMD_ERASE 3

/* XFR 偏移 (0xFA00 基) */
#define XFR_TM0PS   0xFEA0
#define XFR_TM1PS   0xFEA1
#define XFR_TM2PS   0xFEA2
#define XFR_TM3PS   0xFEA3
#define XFR_TM4PS   0xFEA4
#define XFR_T3T4PS  0xFEAC
#define XFR_ADCTIM  0xFEA8
#define XFR_RTCCR   0xFE60
#define XFR_RTCCFG  0xFE61
#define XFR_RTCIEN  0xFE62
#define XFR_RTCIF   0xFE63
#define XFR_SSEC    0xFE76
#define XFR_SEC     0xFE75
#define XFR_I2CCFG  0xFE80
#define XFR_I2CMSCR 0xFE81
#define XFR_I2CMSST 0xFE82
#define XFR_I2CSLST 0xFE84
#define XFR_I2CTXD  0xFE86
#define XFR_I2CRXD  0xFE87
#define XFR_PWMA_CR1  0xFEC0
#define XFR_PWMA_CNTRH 0xFECE
#define XFR_PWMA_CNTRL 0xFECF
#define XFR_PWMA_ARRH  0xFED2
#define XFR_PWMA_ARRL  0xFED3
#define XFR_PWMA_IER   0xFEC4
#define XFR_PWMA_SR1   0xFEC5
#define XFR_PWMA_SR2   0xFEC6
#define XFR_PWMB_CR1   0xFEE0
#define XFR_PWMB_CNTRH 0xFEEE
#define XFR_PWMB_CNTRL 0xFEEF
#define XFR_PWMB_ARRH  0xFEF2
#define XFR_PWMB_ARRL  0xFEF3
#define XFR_PWMB_IER   0xFEE4
#define XFR_PWMB_SR1   0xFEE5
#define XFR_PWMB_SR2   0xFEE6
/* DMA M2M */
#define XFR_DMA_M2M_CFG  0xFA00
#define XFR_DMA_M2M_CR   0xFA01
#define XFR_DMA_M2M_STA  0xFA02
#define XFR_DMA_M2M_AMT  0xFA03
#define XFR_DMA_M2M_DONE 0xFA04
#define XFR_DMA_M2M_TXAH 0xFA05
#define XFR_DMA_M2M_TXAL 0xFA06
#define XFR_DMA_M2M_RXAH 0xFA07
#define XFR_DMA_M2M_RXAL 0xFA08
#define XFR_DMA_M2M_AMTH 0xFA80
#define XFR_DMA_M2M_DONEH 0xFA81

/* CMP / I2C / LVD 行为参数 */
#define CMP_TOGGLE_PERIOD 1000   /* CMPEN 后每 1000 周期模拟输入翻转一次 */
#define I2C_TX_CYCLES     800    /* I2C 主模式发送完成周期 */

/* ------------------------------------------------------------------ */
/* 定时器 T0-T4 (16 位计数 + 自动重装 + 预分频 + 1T/12T)               */
/* ------------------------------------------------------------------ */

static uint16_t timer_cnt_get(MCS251 *c, int which);

/* 定时器 TLx/THx 写 → 更新重装影子 (mem.c 调用)。 */
void mcs251_timer_reload_note(MCS251 *c, int which)
{
    c->t_reload[which] = timer_cnt_get(c, which);
}

static int timer_running(MCS251 *c, int which)
{
    switch (which) {
    case 0: return (c->sfr[0x88 - 0x80] & TCON_TR0) ? 1 : 0;
    case 1: return (c->sfr[0x88 - 0x80] & TCON_TR1) ? 1 : 0;
    case 2: return (c->sfr[0x8E - 0x80] & AUXR_T2R) ? 1 : 0;
    case 3: return (c->sfr[0xDD - 0x80] & T4T3M_T3R) ? 1 : 0;
    case 4: return (c->sfr[0xDD - 0x80] & T4T3M_T4R) ? 1 : 0;
    }
    return 0;
}

/* 1T/12T 选择 + 预分频 (PS+1)。返回: 多少周期计一次。 */
static uint32_t timer_period(MCS251 *c, int which)
{
    int twelve = 0, ps = 0;
    switch (which) {
    case 0: twelve = !(c->sfr[0x8E - 0x80] & AUXR_T0x12);
            ps = c->xfr[XFR_TM0PS - MCS251_XFR_LO]; break;
    case 1: twelve = !(c->sfr[0x8E - 0x80] & AUXR_T1x12);
            ps = c->xfr[XFR_TM1PS - MCS251_XFR_LO]; break;
    case 2: twelve = !(c->sfr[0x8E - 0x80] & AUXR_T2x12);
            ps = c->xfr[XFR_TM2PS - MCS251_XFR_LO]; break;
    case 3: twelve = !(c->sfr[0xDD - 0x80] & T4T3M_T3x12);
            ps = c->xfr[XFR_TM3PS - MCS251_XFR_LO]; break;
    case 4: twelve = !(c->sfr[0xDD - 0x80] & T4T3M_T4x12);
            ps = c->xfr[XFR_TM4PS - MCS251_XFR_LO]; break;
    }
    return (uint32_t)(twelve ? 12 : 1) * (uint32_t)(ps + 1);
}

static uint16_t timer_cnt_get(MCS251 *c, int which)
{
    switch (which) {
    case 0: return (uint16_t)((c->sfr[0x8C - 0x80] << 8) | c->sfr[0x8A - 0x80]);
    case 1: return (uint16_t)((c->sfr[0x8D - 0x80] << 8) | c->sfr[0x8B - 0x80]);
    case 2: return (uint16_t)((c->sfr[0xD6 - 0x80] << 8) | c->sfr[0xD7 - 0x80]);
    case 3: return (uint16_t)((c->sfr[0xD4 - 0x80] << 8) | c->sfr[0xD5 - 0x80]);
    case 4: return (uint16_t)((c->sfr[0xD2 - 0x80] << 8) | c->sfr[0xD3 - 0x80]);
    }
    return 0;
}

static void timer_cnt_set(MCS251 *c, int which, uint16_t v)
{
    switch (which) {
    case 0: c->sfr[0x8C - 0x80] = v >> 8; c->sfr[0x8A - 0x80] = v & 0xFF; break;
    case 1: c->sfr[0x8D - 0x80] = v >> 8; c->sfr[0x8B - 0x80] = v & 0xFF; break;
    case 2: c->sfr[0xD6 - 0x80] = v >> 8; c->sfr[0xD7 - 0x80] = v & 0xFF; break;
    case 3: c->sfr[0xD4 - 0x80] = v >> 8; c->sfr[0xD5 - 0x80] = v & 0xFF; break;
    case 4: c->sfr[0xD2 - 0x80] = v >> 8; c->sfr[0xD3 - 0x80] = v & 0xFF; break;
    }
}

void mcs251_arm_timers(MCS251 *c)
{
    (void)c;
}

/* 定时器溢出 → 置 TF + 中断请求; 16 位自动重装 (模式0/STC32G 默认)。 */
static void timer_overflow(MCS251 *c, int which)
{
    switch (which) {
    case 0: c->sfr[0x88 - 0x80] |= TCON_TF0; break;
    case 1: c->sfr[0x88 - 0x80] |= TCON_TF1; break;
    case 2: c->tf2 = 1; break;
    case 3: c->tf3 = 1; break;
    case 4: c->tf4 = 1; break;
    }
    c->irq_requested = 1;
}

/* 每机器周期调用一次 (1T)。12T 与预分频由调用方折算。 */
static void timer_tick_once(MCS251 *c, int which)
{
    if (!timer_running(c, which))
        return;
    uint16_t cnt = timer_cnt_get(c, which);
    cnt++;
    if (cnt == 0) {
        /* 溢出: 自动重装回装载值 (模式0 = 16位自动重装)。 */
        timer_overflow(c, which);
        timer_cnt_set(c, which, c->t_reload[which]);
    } else {
        timer_cnt_set(c, which, cnt);
    }
}

/* ------------------------------------------------------------------ */
/* UART1-4 (TX + RX 注入)                                               */
/* ------------------------------------------------------------------ */

/* UART TX TI 延迟: 模拟串行发送耗时 (真实硬件 TI 在波特率周期后置位)。
 * 需大于阻塞式发送从写 SBUF 到进入等待循环的指令周期数 (约 10-20),
 * 且足够小以免拖慢大量输出测试 (05 等 21769B × 64 ≈ 1.4M < 20M cycles)。 */
#define UART_TI_DELAY  64

static void uart_tx_common(MCS251 *c, uint8_t ch, uint8_t con_sfr,
                           int irq_en, int con_bit_ti, int uart_no)
{
    if (c->serial_out)
        fputc(ch, c->serial_out);
    /* 模拟串行发送耗时: TI 延迟置位 (真实硬件在波特率周期后置 TI)。
     * 立即置 TI 会在阻塞式发送 (while(!TI)/while(B_TX1)) 进入等待循环前
     * 触发中断 → RETI 后重设忙标志 → 死等 (03-外中断 1B bug)。
     * 输出字节立即写串口文件 (顺序正确), 仅 TI 置位延迟。 */
    c->uart_ti_delay[uart_no] = UART_TI_DELAY;
    c->uart_ti_con[uart_no] = con_sfr;
    c->uart_ti_bit[uart_no] = (uint8_t)con_bit_ti;
    c->uart_ti_irq[uart_no] = irq_en ? 1 : 0;
}

void mcs251_uart_send(MCS251 *c)
{
    uint8_t ch = c->sfr[0x99 - 0x80];
    uart_tx_common(c, ch, 0x98, c->sfr[0xA8 - 0x80] & IE_ES, 1, 0);
}
void mcs251_uart2_send(MCS251 *c)
{
    uint8_t ch = c->sfr[0x9B - 0x80];
#ifdef MCS251_DEBUG_IRQ
    fprintf(stderr, "[U2SEND] ch=%02X ie2=%02X ES2=%d\n", ch,
            c->sfr[0xAF - 0x80], (int)(c->sfr[0xAF - 0x80] & IE2_ES2)!=0);
#endif
    uart_tx_common(c, ch, 0x9A, c->sfr[0xAF - 0x80] & IE2_ES2, 1, 1);
}
void mcs251_uart3_send(MCS251 *c)
{
    uint8_t ch = c->sfr[0xAD - 0x80];
    uart_tx_common(c, ch, 0xAC, c->sfr[0xAF - 0x80] & IE2_ES3, 1, 2);
}
void mcs251_uart4_send(MCS251 *c)
{
    uint8_t ch = c->sfr[0xFE - 0x80];
    uart_tx_common(c, ch, 0xFD, c->sfr[0xAF - 0x80] & IE2_ES4, 1, 3);
}

/* RX 注入 (--input): 字节入 SBUF + RI + 中断 */
/* RX 注入 (--input): 字节入 SBUF RX 缓冲 + RI + 中断.
 * ★ SBUF 读缓冲独立: 写 sfr[0x99] 是 TX 发送缓冲, RX 字节不能覆盖它
 * (真实 8051 SBUF 读写分离; 共享会令 ISR 读 SBUF 得到 TX 字符). */
static void uart_rx_common(MCS251 *c, int uart_no, uint8_t ch)
{
    switch (uart_no) {
    case 0: c->uart_rx_sbuf[0] = ch;
            c->sfr[0x98 - 0x80] |= 0x01;
            c->irq_requested = 1; break;
    case 1: c->uart_rx_sbuf[1] = ch;
            c->sfr[0x9A - 0x80] |= 0x01;
            c->irq_requested = 1; break;
    case 2: c->uart_rx_sbuf[2] = ch;
            c->sfr[0xAC - 0x80] |= 0x01;
            c->irq_requested = 1; break;
    case 3: c->uart_rx_sbuf[3] = ch;
            c->sfr[0xFD - 0x80] |= 0x01;
            c->irq_requested = 1; break;
    }
}

/* ------------------------------------------------------------------ */
/* WDT                                                                 */
/* ------------------------------------------------------------------ */

static uint32_t wdt_timeout_cycles(MCS251 *c)
{
    uint8_t ps = c->sfr[0xC1 - 0x80] & WDT_PS_MASK;
    /* WDT Timeout = (12 * 32768 * SCALE) / SYSclk, SCALE = 2^(PS+1),
       1 sim 周期 = 1/24MHz。=> 周期数 = 12 * 32768 * 2^(PS+1) / 24。 */
    return (uint32_t)(12u * 32768u << (ps + 1)) / 24u;
}

static void wdt_tick(MCS251 *c)
{
    if (!(c->sfr[0xC1 - 0x80] & WDT_EN_WDT))
        return;
    c->wdt_cnt++;
    if (c->wdt_cnt >= wdt_timeout_cycles(c)) {
        /* 看门狗复位: 重启固件 (保留 code/符号表/输出)。 */
        mcs251_reset_keep_io(c);
        c->wdt_cnt = 0;
    }
}

/* ------------------------------------------------------------------ */
/* ADC                                                                 */
/* ------------------------------------------------------------------ */

void mcs251_adc_start(MCS251 *c)
{
    if (!(c->sfr[0xBC - 0x80] & ADC_POWER))
        return;
    /* 转换时间由 ADCCFG.SPEED 决定: 约 2^(9-SPEED) 周期。 */
    uint8_t speed = (c->sfr[0xDE - 0x80] >> 5) & 0x07;
    uint32_t t = 16u << (speed > 4 ? 4 : speed);
    if (t > 4096) t = 4096;
    c->adc_conv_cy = (int)t;
}

static void adc_finish(MCS251 *c)
{
    /* 可编程结果: 通道低 3 位 → 12 位结果 = 0x0300 + ch*0x40 (模拟
       固定电压); 高位 ADC_RES=结果>>4? 按 RESFMT: 0=10bit, 1=12bit。
       默认 RESFMT=0: ADC_RES=高 8 位, ADC_RESL=低 2 位在高 2 bit。 */
    uint8_t ch = c->sfr[0xBC - 0x80] & ADC_CHS;
    uint16_t v = (uint16_t)(0x300u + ((uint16_t)ch << 6)) & 0x3FF;
    if (c->sfr[0xDE - 0x80] & 0x20) {   /* RESFMT=1: 12 位 */
        c->sfr[0xBD - 0x80] = (uint8_t)(v >> 4);
        c->sfr[0xBE - 0x80] = (uint8_t)((v & 0x0F) << 4);
    } else {                            /* RESFMT=0: 10 位 */
        c->sfr[0xBD - 0x80] = (uint8_t)(v >> 2);
        c->sfr[0xBE - 0x80] = (uint8_t)((v & 0x03) << 6);
    }
    c->sfr[0xBC - 0x80] |= ADC_FLAG;    /* 置完成标志 */
    c->sfr[0xBC - 0x80] &= ~ADC_START;
    if (c->sfr[0xA8 - 0x80] & IE_EADC)
        c->irq_requested = 1;
}

/* ------------------------------------------------------------------ */
/* SPI (回环: 收 = 发)                                                 */
/* ------------------------------------------------------------------ */

void mcs251_spi_start(MCS251 *c)
{
    uint8_t speed = c->sfr[0xCE - 0x80] & 0x03;   /* SPR1:0 */
    uint32_t t = 8u << speed;
    if (t > 512) t = 512;
    c->spi_cy = (int)t;
#ifdef MCS251_DEBUG_SPI
    fprintf(stderr, "[SPI-START] t=%d SPIF=%02X\n", (int)t, c->sfr[0xCD - 0x80]);
#endif
}

static void spi_finish(MCS251 *c)
{
    c->sfr[0xCD - 0x80] |= SPIF;
#ifdef MCS251_DEBUG_SPI
    fprintf(stderr, "[SPI-FIN] SPIF=%02X ESPI=%d\n", c->sfr[0xCD - 0x80],
            (int)(c->sfr[0xAF - 0x80] & IE2_ESPI)!=0);
#endif
    /* 回环: SPDAT 内容回读 (从机回同一字节)。 */
    if (c->sfr[0xAF - 0x80] & IE2_ESPI)
        c->irq_requested = 1;
}

/* ------------------------------------------------------------------ */
/* IAP/EEPROM                                                          */
/* ------------------------------------------------------------------ */

void mcs251_iap_trigger(MCS251 *c)
{
    static int iap_seq = 0;
    uint8_t trig = c->sfr[0xC6 - 0x80];
    if (trig == 0x5A) { iap_seq = 1; return; }
    if (trig == 0xA5 && iap_seq == 1) {
        iap_seq = 0;
        if (!(c->sfr[0xC7 - 0x80] & 0x80))  /* IAPEN */
            return;
        uint8_t cmd  = c->sfr[0xC5 - 0x80];
        uint32_t addr = ((uint32_t)(c->sfr[0xF6 - 0x80] & 0x03) << 16)
                      | ((uint32_t)c->sfr[0xC3 - 0x80] << 8)
                      | c->sfr[0xC4 - 0x80];
        addr &= MCS251_EEPROM_SIZE - 1;
        switch (cmd) {
        case IAP_CMD_READ:
            c->sfr[0xC2 - 0x80] = c->eeprom[addr];
            break;
        case IAP_CMD_PROG:
            c->eeprom[addr] = c->sfr[0xC2 - 0x80];
            break;
        case IAP_CMD_ERASE:
            memset(&c->eeprom[addr & ~0x1FF], 0xFF, 512);
            break;
        }
        c->sfr[0xC6 - 0x80] = 0x00;
    } else {
        iap_seq = 0;
    }
}

/* ------------------------------------------------------------------ */
/* RTC (1/128s 秒计数)                                                 */
/* ------------------------------------------------------------------ */

static void rtc_tick(MCS251 *c)
{
    uint8_t rtccr = c->xfr[XFR_RTCCR - MCS251_XFR_LO];
    if (!(rtccr & 0x80))          /* ENRTC */
        return;
    c->rtc_ssec++;
    /* 128 次 1/128s = 1s (sim 周期 ≈ 1/24MHz; 用 24000 周期 ≈ 1ms 标尺,
       1s ≈ 24000000 周期 — 太快。为可观测性, 1s = 128 * 480 周期)。 */
    if (c->rtc_ssec >= 128 * 480) {
        c->rtc_ssec = 0;
        uint8_t sec = c->xfr[XFR_SEC - MCS251_XFR_LO];
        sec++;
        if (sec >= 60) {
            sec = 0;
            uint8_t min = c->xfr[0xFE74 - MCS251_XFR_LO];
            min++;
            if (min >= 60) { min = 0; c->xfr[0xFE73 - MCS251_XFR_LO]++; }
            c->xfr[0xFE74 - MCS251_XFR_LO] = min;
        }
        c->xfr[XFR_SEC - MCS251_XFR_LO] = sec;
    }
    c->xfr[XFR_SSEC - MCS251_XFR_LO] = (uint8_t)(c->rtc_ssec / 480);
}

/* ------------------------------------------------------------------ */
/* PWMA/PWMB (计数 + 更新事件中断)                                     */
/* ------------------------------------------------------------------ */

static void pwm_tick(MCS251 *c, int which)
{
    uint16_t cr1_off = (which == 0) ? XFR_PWMA_CR1 : XFR_PWMB_CR1;
    uint16_t arrh_off = (which == 0) ? XFR_PWMA_ARRH : XFR_PWMB_ARRH;
    uint16_t arl_off = (which == 0) ? XFR_PWMA_ARRL : XFR_PWMB_ARRL;
    uint16_t sr1_off = (which == 0) ? XFR_PWMA_SR1 : XFR_PWMB_SR1;
    uint16_t ier_off = (which == 0) ? XFR_PWMA_IER : XFR_PWMB_IER;
    uint8_t cr1 = c->xfr[cr1_off - MCS251_XFR_LO];
    if (!(cr1 & 0x01))           /* CEN (计数器使能) */
        return;
    /* 预分频: PSC = PSCRH:PSCRL+1 */
    uint16_t psc = (uint16_t)((c->xfr[cr1_off + 0x0A - MCS251_XFR_LO] << 8)
                            | c->xfr[cr1_off + 0x0B - MCS251_XFR_LO]) + 1;
    c->pwm_pre[which]++;
    if (c->pwm_pre[which] < psc)
        return;
    c->pwm_pre[which] = 0;
    uint16_t arr = (uint16_t)((c->xfr[arrh_off - MCS251_XFR_LO] << 8)
                            | c->xfr[arl_off - MCS251_XFR_LO]);
    uint16_t cnt = c->pwm_cnt[which];
    cnt++;
    if (cnt > arr) {
        cnt = 0;
        /* 更新事件: 置 UIF (SR1.0), 若使能则中断 */
        c->xfr[sr1_off - MCS251_XFR_LO] |= 0x01;
        c->pwm_pend |= (uint8_t)(1 << which);
        if (c->xfr[ier_off - MCS251_XFR_LO] & 0x01)   /* UIE */
            c->irq_requested = 1;
    }
    c->pwm_cnt[which] = cnt;
    /* 同步 CNTRH/CNTRL 可读 */
    c->xfr[(which == 0 ? XFR_PWMA_CNTRH : XFR_PWMB_CNTRH) - MCS251_XFR_LO] = (uint8_t)(cnt >> 8);
    c->xfr[(which == 0 ? XFR_PWMA_CNTRL : XFR_PWMB_CNTRL) - MCS251_XFR_LO] = (uint8_t)(cnt & 0xFF);
}

/* ------------------------------------------------------------------ */
/* DMA (M2M 拷贝)                                                      */
/* ------------------------------------------------------------------ */

static void dma_m2m_tick(MCS251 *c)
{
    if (c->dma_m2m_left < 0)
        return;
    if (c->dma_m2m_left == 0) {
        /* 完成 */
        c->dma_m2m_left = -1;
        c->xfr[XFR_DMA_M2M_DONE - MCS251_XFR_LO] = (uint8_t)(c->dma_m2m_amt & 0xFF);
        c->xfr[XFR_DMA_M2M_DONEH - MCS251_XFR_LO] = (uint8_t)(c->dma_m2m_amt >> 8);
        c->xfr[XFR_DMA_M2M_STA - MCS251_XFR_LO] = 0x80;   /* ENF=1 */
        c->xfr[XFR_DMA_M2M_CR - MCS251_XFR_LO] = 0;       /* EN=0 */
        if (c->sfr[0xED - 0x80] & 0x04)   /* DMAIR.DMAIF_M2M */
            c->irq_requested = 1;
        return;
    }
    /* 每次 tick 拷 4 字节 (加速) */
    for (int i = 0; i < 4 && c->dma_m2m_left > 0; i++) {
        c->xram[c->dma_m2m_dst & 0xFFFF] = c->xram[c->dma_m2m_src & 0xFFFF];
        c->dma_m2m_src++; c->dma_m2m_dst++;
        c->dma_m2m_left--;
    }
}

/* ------------------------------------------------------------------ */
/* CMP 比较器 (CMPCR1 0xE6)                                            */
/* ------------------------------------------------------------------ */
/* 模拟输入无法真实采样, 采用周期翻转模型: CMPEN 后每 CMP_TOGGLE_PERIOD
 * 周期比较结果翻转一次 (模拟输入跨阈值), 按边沿类型 (PIE/NIE) 置 CMPIF。
 * CMPRES (bit3) 实时反映比较结果。 */

void mcs251_cmp_enable(MCS251 *c)
{
    c->cmp_sub = 0;
    uint8_t cr = c->sfr[0xE6 - 0x80];
    if (cr & CMP_CMPEN) {
        if (c->cmp_out) cr |= CMP_CMPRES;
        else            cr &= ~CMP_CMPRES;
        c->sfr[0xE6 - 0x80] = cr;
    }
}

static void cmp_tick(MCS251 *c)
{
    uint8_t cr = c->sfr[0xE6 - 0x80];
    if (!(cr & CMP_CMPEN))
        return;
    c->cmp_sub++;
    if (c->cmp_sub < CMP_TOGGLE_PERIOD)
        return;
    c->cmp_sub = 0;
    uint8_t old = c->cmp_out;
    c->cmp_out ^= 1;                       /* 输入跨阈值 → 结果翻转 */
    if (c->cmp_out) cr |= CMP_CMPRES;
    else            cr &= ~CMP_CMPRES;
    /* 边沿中断: 上升沿需 PIE, 下降沿需 NIE */
    if (old == 0 && c->cmp_out && (cr & CMP_PIE)) {
        cr |= CMP_CMPIF; c->irq_requested = 1;
    } else if (old == 1 && !c->cmp_out && (cr & CMP_NIE)) {
        cr |= CMP_CMPIF; c->irq_requested = 1;
    }
    c->sfr[0xE6 - 0x80] = cr;
}

/* ------------------------------------------------------------------ */
/* I2C 硬件 (主模式发送)                                                */
/* ------------------------------------------------------------------ */

void mcs251_i2c_start(MCS251 *c)
{
    if (!(c->xfr[XFR_I2CCFG - MCS251_XFR_LO] & 0x80))   /* ENI2C */
        return;
    c->i2c_busy = 1;
    c->i2c_cy = I2C_TX_CYCLES;
}

static void i2c_tick(MCS251 *c)
{
    if (!c->i2c_busy)
        return;
    if (--c->i2c_cy > 0)
        return;
    c->i2c_busy = 0;
    /* 传输完成: 置 I2CMSST.I2CIF + 挂起中断 */
    c->xfr[XFR_I2CMSST - MCS251_XFR_LO] |= 0x01;
    c->i2c_pend = 1;
    c->irq_requested = 1;
}

/* ------------------------------------------------------------------ */
/* LVD 低压检测 (AUXINTIF.LVDIF)                                       */
/* ------------------------------------------------------------------ */

void mcs251_lvd_trigger(MCS251 *c)
{
    c->sfr[0xEF - 0x80] |= AUXINTIF_LVDIF;
    c->irq_requested = 1;
}

static void lvd_tick(MCS251 *c)
{
    if (c->lvd_cy < 0)
        return;
    if (--c->lvd_cy == 0) {
        c->lvd_cy = -1;
        mcs251_lvd_trigger(c);
    }
}

/* ------------------------------------------------------------------ */
/* XFR 访问 (带副作用)                                                  */
/* ------------------------------------------------------------------ */

uint8_t mcs251_ld_xfr8(MCS251 *c, uint16_t xa)
{
    if (xa < MCS251_XFR_LO)
        return 0xFF;
    uint16_t off = xa - MCS251_XFR_LO;
    if (off >= MCS251_XFR_SIZE)
        return 0xFF;
    /* SPSTAT 读清零在 direct SFR (0xCD), 不走这里。 */
    return c->xfr[off];
}

void mcs251_st_xfr8(MCS251 *c, uint16_t xa, uint8_t v)
{
    if (xa < MCS251_XFR_LO)
        return;
    uint16_t off = xa - MCS251_XFR_LO;
    if (off >= MCS251_XFR_SIZE)
        return;
    /* XFR 写日志 (--trace-xfr) */
    if (c->xfr_trace) {
        if (c->xfr_trace_n < c->xfr_trace_cap) {
            c->xfr_trace[c->xfr_trace_n].cy = c->cycles;
            c->xfr_trace[c->xfr_trace_n].addr = xa;
            c->xfr_trace[c->xfr_trace_n].val = v & 0xFF;
            c->xfr_trace_n++;
        }
    }
    c->xfr[off] = v & 0xFF;
    /* 启动 DMA M2M: 写 DMA_M2M_CR 且 EN=1 */
    if (xa == XFR_DMA_M2M_CR && (v & 0x01)) {
        c->dma_m2m_amt = (uint16_t)(c->xfr[XFR_DMA_M2M_AMT - MCS251_XFR_LO]
                          | (c->xfr[XFR_DMA_M2M_AMTH - MCS251_XFR_LO] << 8));
        c->dma_m2m_src = (uint16_t)((c->xfr[XFR_DMA_M2M_TXAH - MCS251_XFR_LO] << 8)
                          | c->xfr[XFR_DMA_M2M_TXAL - MCS251_XFR_LO]);
        c->dma_m2m_dst = (uint16_t)((c->xfr[XFR_DMA_M2M_RXAH - MCS251_XFR_LO] << 8)
                          | c->xfr[XFR_DMA_M2M_RXAL - MCS251_XFR_LO]);
        c->dma_m2m_left = c->dma_m2m_amt ? (int)c->dma_m2m_amt : -1;
        c->xfr[XFR_DMA_M2M_AMT - MCS251_XFR_LO] = 0;
        c->xfr[XFR_DMA_M2M_AMTH - MCS251_XFR_LO] = 0;
    }
    /* PWMA/PWMB 写 CNTR 同步内部计数 */
    if (xa == XFR_PWMA_CNTRL) c->pwm_cnt[0] = (uint16_t)((c->pwm_cnt[0] & 0xFF00) | v);
    if (xa == XFR_PWMA_CNTRH) c->pwm_cnt[0] = (uint16_t)((c->pwm_cnt[0] & 0x00FF) | ((uint16_t)v << 8));
    if (xa == XFR_PWMB_CNTRL) c->pwm_cnt[1] = (uint16_t)((c->pwm_cnt[1] & 0xFF00) | v);
    if (xa == XFR_PWMB_CNTRH) c->pwm_cnt[1] = (uint16_t)((c->pwm_cnt[1] & 0x00FF) | ((uint16_t)v << 8));
    /* 写 PWMA_SR1/SR2 清更新标志 */
    if (xa == XFR_PWMA_SR1) { c->pwm_pend &= ~1; c->irq_requested = c->irq_requested; }
    if (xa == XFR_PWMB_SR1) { c->pwm_pend &= ~2; }
    /* I2C 主模式发送: 写 I2CTXD (且 ENI2C) → 启动传输 */
    if (xa == XFR_I2CTXD)
        mcs251_i2c_start(c);
}

/* ------------------------------------------------------------------ */
/* 每周期 tick                                                          */
/* ------------------------------------------------------------------ */

void mcs251_soc_cycle(MCS251 *c)
{
    /* 外部脉冲 (演示/激励) */
    if (c->int0_cycles > 0) {
        if (--c->int0_cycles == 0) {
            c->sfr[0x88 - 0x80] |= TCON_IE0;
            c->irq_requested = 1;
        }
    }
    if (c->int2_cycles > 0) {
        if (--c->int2_cycles == 0) {
            c->sfr[0xEF - 0x80] |= AUXINTIF_INT2IF;
            c->irq_requested = 1;
        }
    }
    if (c->int3_cycles > 0) {
        if (--c->int3_cycles == 0) {
            c->sfr[0xEF - 0x80] |= AUXINTIF_INT3IF;
            c->irq_requested = 1;
        }
    }

    /* 定时器 (预分频折算: 每 timer_period 周期计一次) */
    for (int t = 0; t < 5; t++) {
        uint32_t period = timer_period(c, t);
        c->t_sub[t]++;
        if (c->t_sub[t] >= period) {
            c->t_sub[t] = 0;
            timer_tick_once(c, t);
        }
    }

    /* UART TX: TI 延迟置位 (模拟串行发送耗时, 见 uart_tx_common) */
    for (int u = 0; u < 4; u++) {
        if (c->uart_ti_delay[u]) {
            if (--c->uart_ti_delay[u] == 0) {
                c->sfr[c->uart_ti_con[u] - 0x80] |=
                    (uint8_t)(1 << c->uart_ti_bit[u]);
                if (c->uart_ti_irq[u])
                    c->irq_requested = 1;
            }
        }
    }

    /* UART RX 注入 */
    for (int u = 0; u < 4; u++) {
        if (c->uart_rx_pend[u]) {
            c->uart_rx_pend[u] = 0;
            uart_rx_common(c, u, c->uart_rx[u]);
        }
    }

    /* UART RX 注入 (--input): 每 800 周期注 1 字节到 UART1。
     * g_rx_last_cy 可为延迟起点 (>0), 需防无符号下溢: cycles < 起点时不注入。
     * ★ 等 UART1 使能 (EA=1 且 ES=1) 再开始注入 — 模拟真实场景 (PC 在
       MCU 初始化完成后才发数据)。注入过早 (TCC 编译慢, UART 配置完成晚
       — 09 双串口 EA=1 在 26880, 注入 20000 起) 会在 EA=0 前置位 RI,
       poll 忽略 (EA=0 return 0), 6 字节注入只处理最后 1 个 (09 只回显
       1B 根因)。 */
    if (g_rx_buf && g_rx_i < g_rx_n) {
        uint8_t ie_ = c->sfr[0xA8 - 0x80];
        uint8_t ie2_ = c->sfr[0xAF - 0x80];
        int uart1_ready = (ie_ & IE_EA) && (ie_ & IE_ES);
        if (uart1_ready && c->cycles >= g_rx_last_cy
            && (uint64_t)(c->cycles - g_rx_last_cy) >= 800) {
            g_rx_last_cy = c->cycles;
            mcs251_uart_rx_inject(c, 0, g_rx_buf[g_rx_i++]);
        }
    }

    /* WDT */
    wdt_tick(c);

    /* ADC */
    if (c->adc_conv_cy >= 0) {
        if (--c->adc_conv_cy == 0)
            adc_finish(c);
    }

    /* SPI */
    if (c->spi_cy >= 0) {
        if (--c->spi_cy == 0)
            spi_finish(c);
    }

    /* RTC */
    rtc_tick(c);

    /* PWM */
    pwm_tick(c, 0);
    pwm_tick(c, 1);

    /* DMA */
    dma_m2m_tick(c);

    /* CMP / I2C / LVD */
    cmp_tick(c);
    i2c_tick(c);
    lvd_tick(c);
}

/* ------------------------------------------------------------------ */
/* 中断控制器                                                           */
/* ------------------------------------------------------------------ */

/* 是否有挂起且使能的中断 (RETI 后检查: ISR 未清标志则立即重入 —
 * 8051 语义; 并发中断如 UART TX TI + RX RI 重叠不会丢失) */
int mcs251_irq_pending(MCS251 *c)
{
    uint8_t ie   = c->sfr[0xA8 - 0x80];
    uint8_t ie2  = c->sfr[0xAF - 0x80];
    uint8_t tcon = c->sfr[0x88 - 0x80];
    uint8_t intclko = c->sfr[0x8F - 0x80];
    uint8_t auxif = c->sfr[0xEF - 0x80];
    uint8_t scon = c->sfr[0x98 - 0x80];
    uint8_t s2con = c->sfr[0x9A - 0x80];
    uint8_t s3con = c->sfr[0xAC - 0x80];
    uint8_t s4con = c->sfr[0xFD - 0x80];
    uint8_t adccon = c->sfr[0xBC - 0x80];
    uint8_t spstat = c->sfr[0xCD - 0x80];
    uint8_t cmpcr1 = c->sfr[0xE6 - 0x80];
    if ((ie & IE_EA) == 0)
        return 0;
    if ((ie & IE_EX0) && (tcon & TCON_IE0)) return 1;
    if ((ie & IE_ET0) && (tcon & TCON_TF0)) return 1;
    if ((ie & IE_EX1) && (tcon & TCON_IE1)) return 1;
    if ((ie & IE_ET1) && (tcon & TCON_TF1)) return 1;
    if ((ie & IE_ES) && (scon & 0x03)) return 1;
    if ((ie & IE_EADC) && (adccon & ADC_FLAG)) return 1;
    if ((ie & IE_ELVD) && (auxif & AUXINTIF_LVDIF)) return 1;
    if ((ie2 & IE2_ES2) && (s2con & 0x03)) return 1;
    if ((ie2 & IE2_ESPI) && (spstat & SPIF)) return 1;
    if ((intclko & INTCLKO_EX2) && (auxif & AUXINTIF_INT2IF)) return 1;
    if ((intclko & INTCLKO_EX3) && (auxif & AUXINTIF_INT3IF)) return 1;
    if ((ie2 & IE2_ET2) && c->tf2) return 1;
    if ((intclko & INTCLKO_EX4) && (auxif & AUXINTIF_INT4IF)) return 1;
    if ((ie2 & IE2_ES3) && (s3con & 0x03)) return 1;
    if ((ie2 & IE2_ES4) && (s4con & 0x03)) return 1;
    if ((ie2 & IE2_ET3) && c->tf3) return 1;
    if ((ie2 & IE2_ET4) && c->tf4) return 1;
    if ((cmpcr1 & (CMP_PIE | CMP_NIE)) && (cmpcr1 & CMP_CMPIF)) return 1;
    if ((c->xfr[XFR_I2CMSCR - MCS251_XFR_LO] & 0x80) && c->i2c_pend) return 1;
    if ((c->xfr[XFR_PWMA_IER - MCS251_XFR_LO] & 0x01) && (c->pwm_pend & 1)) return 1;
    if ((c->xfr[XFR_PWMB_IER - MCS251_XFR_LO] & 0x01) && (c->pwm_pend & 2)) return 1;
    return 0;
}

/* 取一个挂起且使能的中断。返回向量地址; 0 = 无。 */
int mcs251_poll_interrupt(MCS251 *c)
{
    if (!c->irq_requested)
        return 0;
    /* ★ 中断处理中不重入 (8051: 中断响应硬件清 EA, RETI 恢复)。
       ISR 未执行完 (未清 RI/TI) 时新中断挂起, 不打断当前 ISR */
    if (c->in_isr)
        return 0;
    c->irq_requested = 0;

    uint8_t ie   = c->sfr[0xA8 - 0x80];
    uint8_t ie2  = c->sfr[0xAF - 0x80];
    uint8_t tcon = c->sfr[0x88 - 0x80];
    uint8_t intclko = c->sfr[0x8F - 0x80];
    uint8_t auxif = c->sfr[0xEF - 0x80];
    uint8_t scon = c->sfr[0x98 - 0x80];
    uint8_t s2con = c->sfr[0x9A - 0x80];
    uint8_t s3con = c->sfr[0xAC - 0x80];
    uint8_t s4con = c->sfr[0xFD - 0x80];
    uint8_t adccon = c->sfr[0xBC - 0x80];
    uint8_t spstat = c->sfr[0xCD - 0x80];
    uint8_t cmpcr1 = c->sfr[0xE6 - 0x80];
    uint16_t vec = 0;

    if ((ie & IE_EA) == 0)
        return 0;

#ifdef MCS251_DEBUG_IRQ
    if (s2con & 0x03) {
        fprintf(stderr, "[IRQ-DBG] ie=%02X ie2=%02X scon=%02X s2con=%02X\n",
                ie, ie2, scon, s2con);
    }
#endif

    /* 固定优先级: 向量号小者优先 (STC32G 同级中断按向量序)。 */
    if ((ie & IE_EX0) && (tcon & TCON_IE0)) {
        vec = VEC_INT0; c->sfr[0x88 - 0x80] = tcon & ~TCON_IE0;
    } else if ((ie & IE_ET0) && (tcon & TCON_TF0)) {
        vec = VEC_T0;   c->sfr[0x88 - 0x80] = tcon & ~TCON_TF0;
    } else if ((ie & IE_EX1) && (tcon & TCON_IE1)) {
        vec = VEC_INT1; c->sfr[0x88 - 0x80] = tcon & ~TCON_IE1;
    } else if ((ie & IE_ET1) && (tcon & TCON_TF1)) {
        vec = VEC_T1;   c->sfr[0x88 - 0x80] = tcon & ~TCON_TF1;
    } else if ((ie & IE_ES) && (scon & 0x03)) {
        vec = VEC_SIO;   /* RI/TI 由 ISR 软件清 (8051 约定, 非硬件自动清) */
    } else if ((ie & IE_EADC) && (adccon & ADC_FLAG)) {
        vec = VEC_ADC;  c->sfr[0xBC - 0x80] = adccon & ~ADC_FLAG;
    } else if ((ie & IE_ELVD) && (auxif & AUXINTIF_LVDIF)) {
        vec = VEC_LVD;  c->sfr[0xEF - 0x80] = auxif & ~AUXINTIF_LVDIF;
    } else if ((ie2 & IE2_ES2) && (s2con & 0x03)) {
        vec = VEC_SIO2;  /* RI/TI 由 ISR 软件清 */
#ifdef MCS251_DEBUG_IRQ
        fprintf(stderr, "[IRQ-VEC] UART2 s2con=%02X\n", s2con);
#endif
    } else if ((ie2 & IE2_ESPI) && (spstat & SPIF)) {
        vec = VEC_SPI;  c->sfr[0xCD - 0x80] = spstat & ~SPIF;
    } else if ((intclko & INTCLKO_EX2) && (auxif & AUXINTIF_INT2IF)) {
        vec = VEC_INT2; c->sfr[0xEF - 0x80] = auxif & ~AUXINTIF_INT2IF;
    } else if ((intclko & INTCLKO_EX3) && (auxif & AUXINTIF_INT3IF)) {
        vec = VEC_INT3; c->sfr[0xEF - 0x80] = auxif & ~AUXINTIF_INT3IF;
    } else if ((ie2 & IE2_ET2) && c->tf2) {
        vec = VEC_T2;   c->tf2 = 0;
    } else if ((intclko & INTCLKO_EX4) && (auxif & AUXINTIF_INT4IF)) {
        vec = VEC_INT4; c->sfr[0xEF - 0x80] = auxif & ~AUXINTIF_INT4IF;
    } else if ((ie2 & IE2_ES3) && (s3con & 0x03)) {
        vec = VEC_SIO3;  /* RI/TI 由 ISR 软件清 */
    } else if ((ie2 & IE2_ES4) && (s4con & 0x03)) {
        vec = VEC_SIO4;  /* RI/TI 由 ISR 软件清 */
    } else if ((ie2 & IE2_ET3) && c->tf3) {
        vec = VEC_T3;   c->tf3 = 0;
    } else if ((ie2 & IE2_ET4) && c->tf4) {
        vec = VEC_T4;   c->tf4 = 0;
    } else if ((cmpcr1 & (CMP_PIE | CMP_NIE)) && (cmpcr1 & CMP_CMPIF)) {
        vec = VEC_CMP;  c->sfr[0xE6 - 0x80] = cmpcr1 & ~CMP_CMPIF;
    } else if ((c->xfr[XFR_I2CMSCR - MCS251_XFR_LO] & 0x80) && c->i2c_pend) {
        vec = VEC_I2C;  c->i2c_pend = 0;
    } else if ((c->xfr[XFR_PWMA_IER - MCS251_XFR_LO] & 0x01) && (c->pwm_pend & 1)) {
        vec = VEC_PWMA; c->pwm_pend &= ~1;
        c->xfr[XFR_PWMA_SR1 - MCS251_XFR_LO] &= ~0x01;
    } else if ((c->xfr[XFR_PWMB_IER - MCS251_XFR_LO] & 0x01) && (c->pwm_pend & 2)) {
        vec = VEC_PWMB; c->pwm_pend &= ~2;
        c->xfr[XFR_PWMB_SR1 - MCS251_XFR_LO] &= ~0x01;
    } else {
        return 0;
    }

    /* Push PC (低字节, 再高字节) — 必须用 16 位 SPX (与 cpu.c push_pc 一致)。
     * 原实现只用 8 位 rf[RF_SPX], SP>0xFF 时低字节回绕写坏低地址 (栈底),
     * 且不回绕 SPH — 中断触发即栈破坏 → RET 逃逸 (Keil 2-12 等 RETVIO 根因)。 */
    {
        uint16_t sp = (uint16_t)(c->rf[RF_SPX] | (c->rf[RF_SPX + 1] << 8));
        sp++;
        c->iram[sp & (MCS251_IRAM_SIZE - 1)] = c->pc & 0xFF;
        sp++;
        c->iram[sp & (MCS251_IRAM_SIZE - 1)] = (c->pc >> 8) & 0xFF;
        c->rf[RF_SPX] = sp & 0xFF;
        c->rf[RF_SPX + 1] = (sp >> 8) & 0xFF;
    }
    if (g_trace_stkwr)
        fprintf(stderr, "[IRQ] vec=%04X pc=%04X SP=%04X cy=%llu\n",
                vec, c->pc,
                (unsigned)(c->rf[RF_SPX] | (c->rf[RF_SPX + 1] << 8)),
                (unsigned long long)c->cycles);
    /* RET 一致性: 中断入口 push 的 PC 也是合法 RETI 目标 */
    c->ret_pushed[c->pc >> 3] |= (uint8_t)(1 << (c->pc & 7));
    c->pc = vec;
    /* 中断响应: 硬件清 EA 等效 — 屏蔽后续中断直到 RETI (8051 语义) */
    c->in_isr = 1;
    return 1;
}

/* 供外部 (main.c --input) 注入 UART 字节。uart_no: 0-3。 */
void mcs251_uart_rx_inject(MCS251 *c, int uart_no, uint8_t ch)
{
    if (uart_no >= 0 && uart_no < 4) {
        c->uart_rx[uart_no] = ch;
        c->uart_rx_pend[uart_no] = 1;
    }
}
