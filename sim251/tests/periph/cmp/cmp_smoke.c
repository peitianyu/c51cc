/*
 * cmp_smoke.c — 比较器冒烟测试: CMPEN → CMPRES 翻转。
 *
 * sim251 CMP 模型: CMPEN=1 后每 CMP_TOGGLE_PERIOD=1000 周期
 * 模拟输入翻转一次, CMPCR1 (0xE6).CMPRES (bit3) 随之变化。
 *
 * 预期 CMPCR1 & 0x08 (CMPRES) 置位 (经过若干翻转周期后)。
 */
typedef unsigned char u8;

sfr CMPCR1 = 0xE6;

void main(void)
{
	CMPCR1 = 0x80;    /* CMPEN=1 */
	for (;;) {
		/* 等 CMPRES 置位 (翻转到达) */
		;
	}
}
