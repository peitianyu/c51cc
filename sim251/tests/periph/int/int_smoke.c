/*
 * int_smoke.c — 外部中断 INT0 冒烟测试: sim --int0 脉冲 → ISR 执行。
 *
 * 默认 int0_cycles=1000 在 TCC 启动代码 (~3200cy) 之前触发,
 * 需在 run_periph.py 中传递 --int0 参数 (cycle>4000)。
 * ISR 执行后写 P1=0xAA 标记。
 *
 * 预期 P1 (0x90) == 0xAA (ISR 执行过)。
 */
typedef unsigned char u8;

sfr IE   = 0xA8;
sfr P1   = 0x90;

sbit EX0 = IE ^ 0;
sbit EA  = IE ^ 7;

void INT0_ISR(void) interrupt 0
{
	P1 = 0xAA;
}

void main(void)
{
	u8 i;
	/* 延时等 INT0 脉冲 (需 run_periph.py extra_args --int0 4500) */
	for (i = 0; i < 100; i++) ;
	EX0 = 1;
	EA  = 1;
	for (i = 0; i < 100; i++) ;  /* 等待中断 */
	P1 = (P1 == 0xAA) ? 0xAA : 0xBB;  /* 保险: 若未触发则标记 0xBB */
	for (;;) { ; }
}
