/*
 * uart_smoke.c — UART1 冒烟测试: SFR 直接操作 + TI 轮询发送。
 *
 * 目的: 验证 sim251 UART1 TX 模型。写 SBUF (0x99) 后:
 *   1) 字节写入 --serial 输出文件
 *   2) SCON (0x98).TI (bit1) 置位
 *   3) 软件清 TI 后可继续发下一字节
 *
 * 约束: sim251 的 UART 中断驱动路径存在已知 bug (只输出 1 字节, 主线程修),
 *       本测试用 TI 轮询 (不依赖中断路径), 保证框架不依赖该 bug。
 *
 * 预期串口输出 (13 字节, 与 Keil ref 一致):
 *   "UART_SMOKE_OK\r\n"
 */
typedef unsigned char u8;

sfr SCON = 0x98;
sfr SBUF = 0x99;

sbit TI = SCON ^ 1;

/* 发送单字节: 写 SBUF → 等 TI → 清 TI (sim 写 SBUF 立即置 TI) */
void uart_putc(u8 c)
{
	SBUF = c;
	while (!TI)
		;
	TI = 0;
}

void main(void)
{
	SCON = 0x40;            /* mode 1, 8-bit UART, 禁用 REN */
	/* 输出已知字符串 "UART_SMOKE_OK\r\n"。
	 * 注意: 用字面量逐字节发送 (不用 const char msg[] / 字符串指针) —
	 * TCC C251 当前对初始化字符串/数组的 INITEDATA 拷贝生成有缺口,
	 * 字符串字面量在代码空间而读用数据空间地址 → 读到 0 (见 README)。 */
	uart_putc('U'); uart_putc('A'); uart_putc('R'); uart_putc('T');
	uart_putc('_'); uart_putc('S'); uart_putc('M'); uart_putc('O');
	uart_putc('K'); uart_putc('E'); uart_putc('_'); uart_putc('O');
	uart_putc('K'); uart_putc('\r'); uart_putc('\n');
	for (;;) {
		/* 挂起: 不能返回 (返回触发 sim RESTART 覆盖状态) */
	}
}
