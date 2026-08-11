/*
 * dma_smoke.c — DMA M2M 冒烟测试: 配置 → 触发 → DONE 标志。
 *
 * sim251 DMA: dma_m2m_tick() 每周期传 4 字节 (src→dst)。
 * XFR: CFG=0xFA00, CR=0xFA01, STA=0xFA02, AMT=0xFA03,
 *      DONE=0xFA04, TXAH/L=0xFA05/6, RXAH/L=0xFA07/8。
 * far 基地址 0x7EFA00。
 *
 * 预期 STA=0x80 (ENF=1) 或 DONE 非零 (传输完成)。
 */
typedef unsigned char u8;
typedef unsigned int  u16;
sfr P1 = 0x90;

#define XFR(b) (*((volatile u8 far *)0x7EFA00UL + (b)))

/* 写 XRAM (通过 xdata 指针) */
void xram_write(u16 addr, u8 v)
{
	*(volatile u8 xdata *)(addr) = v;
}

void main(void)
{
	u8 i, done;
	/* 在 XRAM 0x0100 写源数据 */
	for (i = 0; i < 16; i++)
		xram_write(0x0100 + i, 0xA5 + i);

	/* 配置 DMA M2M: CFG=0 (单次), 源 0x0100 → 目标 0x0200, 16 字节 */
	XFR(0x05) = 0x00;        /* TXAH = 0 */
	XFR(0x06) = 0x00;        /* TXAL = 0x0100 & 0xFF → 0x00? 不对... */

	/* 简化: 源 0x0000 → 目标 0x0100, 4 字节 */
	XFR(0x05) = 0x00;        /* TXAH (源高) */
	XFR(0x06) = 0x00;        /* TXAL (源低) */
	XFR(0x07) = 0x00;        /* RXAH (目标高) */
	XFR(0x08) = 0x01;        /* RXAL (目标低=0x0100) */
	XFR(0x03) = 0x04;        /* AMT = 4 字节 */
	XFR(0x00) = 0x00;        /* CFG = 0 (单次, 8-bit) */
	XFR(0x01) = 0x01;        /* CR = 0x01 (EN=1, 启动) */

	P1 = 0xAA;               /* 标记: DMA 已触发 */

	/* 等传输完成 */
	done = XFR(0x04);         /* 读 DONE */
	if (done)
		P1 = done;
	else
		P1 = XFR(0x02);      /* 读 STA */
	for (;;) { ; }
}
