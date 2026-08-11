/*
 * rtc_smoke.c — RTC 冒烟测试: 使能 RTC → SSEC 递增。
 *
 * sim251 RTC: rtc_tick() 每 480 周期 SSEC 递增 1, 128 SSEC=1 SEC。
 * XFR: RTCCR=0xFE60, SSEC=0xFE76, SEC=0xFE75。
 * far 基地址 0x7EFE00。
 *
 * 预期 SSEC > 0 (经过数千周期后)。
 */
typedef unsigned char u8;
sfr P1 = 0x90;

void main(void)
{
	volatile u8 far *xf = (volatile u8 far *)0x7EFE00UL;
	volatile u8 v;
	unsigned int i;
	xf[0x60] = 0x80;         /* RTCCR: ENRTC=1 (bit7) */
	P1 = 0xAA;               /* 标记: RTC 已使能 */

	/* 等 RTC 走若干 SSEC: 480cy/SSEC, 循环 ~5000cy ≈ 10 SSEC */
	for (i = 0; i < 1000; i++) ;
	v = xf[0x76];            /* 读 SSEC */
	P1 = v;                  /* 输出 SSEC 值 (应 > 0) */
	for (;;) { ; }
}
