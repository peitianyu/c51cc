/*
 * timer_isr.c — Timer0 中断触发测试: 溢出 → Timer0 ISR 递增计数并写 P1。
 *
 * 目的: 验证 sim251 Timer0 中断完整链路:
 *   1) Timer0 1T 快速溢出 → TF0 置位
 *   2) ET0+EA 使能 → 中断向量 0x0B 跳入 ISR (硬件自动清 TF0)
 *   3) ISR 递增 volatile t0_cnt, 写 P1 供 dump 验证
 *
 * 预期 (dump-ram, 5000 周期):
 *   SFR:0x90 (P1) != 0          → ISR 至少执行过
 *   volatile t0_cnt (IRAM) > 0  → 中断被触发多次
 */
typedef unsigned char u8;
typedef unsigned int  u16;

sfr TCON = 0x88;
sfr TMOD = 0x89;
sfr TL0  = 0x8A;
sfr TH0  = 0x8C;
sfr AUXR = 0x8E;
sfr IE   = 0xA8;
sfr P1   = 0x90;

sbit TR0  = TCON ^ 4;
sbit TF0  = TCON ^ 5;
sbit T0x12 = AUXR ^ 7;
sbit ET0  = IE ^ 1;
sbit EA   = IE ^ 7;

/* ISR 共享变量 (volatile) */
volatile u16 t0_irq_cnt;
volatile u8  t0_flag;

/* Timer0 ISR (interrupt 1 → 向量 0x0B), TF0 硬件自动清 */
void Timer0_ISR(void) interrupt 1
{
	t0_irq_cnt++;
	t0_flag = 1;
	P1 = (u8)(t0_irq_cnt & 0xFF);   /* 写 P1 供 dump 验证 */
}

void main(void)
{
	AUXR |= 0x80;           /* T0x12 = 1 (1T) */
	TMOD = 0x00;            /* 16-bit auto-reload */
	TL0  = 0xE0;
	TH0  = 0xFF;            /* 重装 0xFFE0, 32 周期溢出 */
	ET0  = 1;
	EA   = 1;
	TR0  = 1;               /* 启动 */
	for (;;) {
		/* 挂起: 中断驱动 t0_irq_cnt */
	}
}
