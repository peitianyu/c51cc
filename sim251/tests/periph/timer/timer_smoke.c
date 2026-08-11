/*
 * timer_smoke.c — Timer0 冒烟测试: 1T 模式快速溢出 → TF0 置位 + 自动重装。
 *
 * 目的: 验证 sim251 Timer0 模型:
 *   1) TMOD=0 (16 位自动重装), AUXR.T0x12=1 (1T)
 *   2) 重装值 0xFFE0 → 32 个 sim 周期后计数溢出
 *   3) 溢出 → TCON.TF0 (bit5) 置位, 计数自动回重装值
 *
 * 预期 (dump-ram, 2000 周期):
 *   SFR:0x88 含 bit 0x20 (TF0)
 *   SFR:0x8C = 0xFF, SFR:0x8A = 0xE0 (自动重装回初值)
 */
typedef unsigned char u8;

sfr TCON = 0x88;
sfr TMOD = 0x89;
sfr TL0  = 0x8A;
sfr TH0  = 0x8C;
sfr AUXR = 0x8E;

sbit TR0  = TCON ^ 4;
sbit TF0  = TCON ^ 5;
sbit T0x12 = AUXR ^ 7;

void main(void)
{
	AUXR |= 0x80;           /* T0x12 = 1 (1T) */
	TMOD = 0x00;            /* mode 0: 16-bit auto-reload */
	TL0  = 0xE0;
	TH0  = 0xFF;            /* 重装 0xFFE0, 32 周期溢出 */
	TR0  = 1;               /* 启动 */
	for (;;) {
		/* 挂起: 让 TF0 置位 (无 ISR 不会被清) */
	}
}
