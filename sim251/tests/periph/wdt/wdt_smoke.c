/*
 * wdt_smoke.c — 看门狗冒烟测试: WDT 使能 + 喂狗 + 无复位。
 *
 * sim251 WDT 模型: WDT_EN_WDT=1 后 wdt_cnt 累加, 超时触发 reset_keep_io。
 * 定期写 WDT_CLR_WDT (0x10) 清零计数器避免复位。
 *
 * 预期程序安全跑满 cycles 无 ESCAPE/RESTART。
 */
typedef unsigned char u8;
typedef unsigned int  u16;

sfr WDT_CONTR = 0xC1;
sfr P1 = 0x90;

void main(void)
{
	WDT_CONTR = 0x24;   /* EN_WDT=1, PS=4 (timeout ~1M cy) */
	P1 = 0xAA;          /* 标记: 已进入 main */
	WDT_CONTR = 0x34;   /* EN_WDT=1 + CLR_WDT (喂狗, wdt_cnt=0) */
	P1 = 0xCC;          /* 标记: 喂狗完成, 安全 */
	for (;;) { ; }
}
