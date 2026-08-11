/*
 * pwm_smoke.c — PWM 冒烟测试: 使能 PWMA → 计数器递增。
 *
 * sim251 PWM: pwm_tick() 按预分频递增 pwm_cnt。
 * XFR: PWMA_CR1=0xFEC0, PWMA_ARRH=0xFED2, PWMA_ARRL=0xFED3,
 *      PWMA_CNTRH=0xFECE, PWMA_CNTRL=0xFECF。
 * far 基地址 0x7EFE00。
 *
 * 预期 PWMA_CNTR > 0 (计数开始递增)。
 */
typedef unsigned char u8;
sfr P1 = 0x90;

#define XFR(b) (*((volatile u8 far *)0x7EFE00UL + (b)))

void main(void)
{
	u8 lo;
	XFR(0xD3) = 0xFF;        /* PWMA_ARRL = 0xFF (周期) */
	XFR(0xD2) = 0x00;        /* PWMA_ARRH = 0x00 */
	XFR(0xC0) = 0x01;        /* PWMA_CR1 = 0x01 (使能计数器) */
	P1 = 0xAA;               /* 标记: PWM 已使能 */

	/* PWM 每 (PSC+1) 周期递增; 5000cy 内应已累加 */
	lo = XFR(0xCF);           /* 读 PWMA_CNTRL */
	P1 = lo;                  /* 输出低字节 (应非零) */
	for (;;) { ; }
}
