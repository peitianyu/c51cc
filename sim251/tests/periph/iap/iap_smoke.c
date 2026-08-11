/*
 * iap_smoke.c — IAP/EEPROM 冒烟测试: 擦除扇区 + 编程字节 + 读取校验。
 *
 * sim251 IAP 模型: iap_trigger() 擦除 (全扇区 0xFF) / 编程 (写字节) / 读取。
 * EEPROM 大小 4KB (0x1000), IAP_ADDRL/H 16 位地址。
 *
 * 预期 IAP_DATA (0xC2) == 0x5A (编程后读取一致)。
 */
typedef unsigned char u8;
typedef unsigned int  u16;

sfr IAP_DATA   = 0xC2;
sfr IAP_ADDRH  = 0xC3;
sfr IAP_ADDRL  = 0xC4;
sfr IAP_CMD    = 0xC5;
sfr IAP_TRIG   = 0xC6;
sfr IAP_CONTR  = 0xC7;
sfr P1         = 0x90;

/* 触发 IAP */
void iap_go(void)
{
	IAP_TRIG = 0x5A;
	IAP_TRIG = 0xA5;
}

void main(void)
{
	u8 v;
	IAP_CONTR  = 0x80;     /* IAPEN=1 */
	IAP_ADDRH  = 0x00;     /* 地址 0x0000 */
	IAP_ADDRL  = 0x00;
	IAP_CMD    = 0x03;     /* ERASE */
	iap_go();

	IAP_CMD    = 0x02;     /* PROGRAM */
	IAP_DATA   = 0x5A;
	iap_go();

	IAP_CMD    = 0x01;     /* READ */
	iap_go();
	v = IAP_DATA;
	/* v == 0x5A → 写 P1 标记 */
	P1 = v;

	for (;;) { ; }
}
