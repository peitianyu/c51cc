/*
 * spi_smoke.c — SPI 冒烟测试: SPDAT 写 → SPIF 标志置位。
 *
 * sim251 SPI 模型: 写 SPDAT (0xCF) 触发 spi_start(), 固定延迟后
 * spi_finish() 置 SPIF (SPSTAT.7=0x80), 结果放入 SPDAT。
 *
 * ★ STC32G 硬件行为: 读 SPSTAT 清 SPIF! 不可轮询, 直接写后挂起。
 *
 * 预期 SPSTAT & 0x80 (SPIF) 置位 (dump SFR 验证)。
 */
typedef unsigned char u8;

sfr SPCTL  = 0xCE;
sfr SPDAT  = 0xCF;

void main(void)
{
	SPCTL = 0xD0;       /* SSIG=1, SPE=1, DORD=0, MSTR=1, CPOL/CPHA=0 */
	SPDAT = 0x55;       /* 写数据触发 SPI 传输 (~8 周期后 SPIF 置位) */
	for (;;) { ; }      /* 挂起: 不读 SPSTAT, 靠 dump 验证 SPIF */
}
