/*
 * i2c_smoke.c — I2C 冒烟测试: 配置 → 写 TXD → 检查完成状态。
 *
 * sim251 I2C: 写 I2CTXD 触发 i2c_tick(), I2C_TX_CYCLES=800 后完成。
 * XFR: I2CCFG=0xFE80, I2CMSCR=0xFE81, I2CMSST=0xFE82,
 *      I2CTXD=0xFE86, I2CRXD=0xFE87。
 * far 基地址 0x7EFE00。
 *
 * 预期 I2CMSST & 0x40 (MSBUSY 清? 或完成标志)。
 */
typedef unsigned char u8;
sfr P1 = 0x90;

void main(void)
{
	volatile u8 far *xf = (volatile u8 far *)0x7EFE00UL;
	volatile u8 st;
	unsigned int i;
	xf[0x80] = 0x80;         /* I2CCFG: ENI2C=1 (bit7) */
	xf[0x86] = 0x5A;         /* I2CTXD → 写自动触发 i2c_start */

	P1 = 0xAA;               /* 标记: I2C 已触发 */

	/* 等 I2C 传输完成: I2C_TX_CYCLES=800, 循环 ~2000cy */
	for (i = 0; i < 500; i++) ;
	st = xf[0x82];           /* 读 I2CMSST */
	P1 = st;                 /* 输出状态 (应非零) */
	for (;;) { ; }
}
