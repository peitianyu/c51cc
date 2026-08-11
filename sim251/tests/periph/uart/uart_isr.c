/*
 * uart_isr.c — UART1 中断驱动发送测试 (SFR 直操作 + UART ISR)。
 *
 * 目的: 走完整 UART 中断路径:
 *   main 写 SBUF → sim 置 TI + 触发 UART 中断 (VEC 0x23) →
 *   ISR 清 TI, 发下一字节 → 主循环继续。
 *
 * 预期: 串口输出 "ABCDEFGHIJKLM" (13 字节)。
 *
 * 注意: 发送序列用"算术"生成 ('A'+i, 无数组/字符串) — 避开 TCC 对
 * 字符串初始化与多 volatile 全局数组布局的已知缺口 (见 README)。
 */
typedef unsigned char u8;

sfr SCON = 0x98;
sfr SBUF = 0x99;
sfr IE   = 0xA8;

sbit TI = SCON ^ 1;
sbit RI = SCON ^ 0;
sbit ES = IE   ^ 4;
sbit EA = IE   ^ 7;

/* ISR 共享 (volatile, 跨中断) */
volatile u8  tx_phase;     /* 已发送字节数 (0-13) */
volatile u8  uart_irq_cnt; /* ISR 触发计数 */

/* UART1 中断服务 (interrupt 4 → 向量 0x23) */
void UART1_ISR(void) interrupt 4
{
	if (TI) {
		TI = 0;
		if (tx_phase < 13) {
			SBUF = (u8)(0x41 + tx_phase);   /* 'A'..'M' */
			tx_phase++;
		}
		uart_irq_cnt++;
	}
	if (RI)
		RI = 0;
}

void main(void)
{
	SCON = 0x40;            /* mode 1, 8-bit UART */
	ES = 1;                 /* IE bit4 = ES (UART1 中断使能) */
	EA = 1;                 /* 全局中断使能 */
	tx_phase = 1;
	SBUF = 'A';             /* 写首字节触发首个 TI 中断 */
	for (;;) {
		/* 挂起: 中断驱动发送 'B'..'M' */
	}
}
