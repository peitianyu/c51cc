/*
 * adc_smoke.c — ADC 冒烟测试: 上电 + 启动转换 → 完成标志 + 结果寄存器。
 *
 * 目的: 验证 sim251 ADC 模型 (STC32G SFR):
 *   ADC_CONTR (0xBC): bit7=ADC_POWER, bit6=ADC_START, bit5=ADC_FLAG
 *   ADC_RES (0xBD) / ADC_RESL (0xBE): 10 位结果 (RESFMT=0)
 *
 * 流程: ADC_POWER=1 → ADC_START=1 → 转换 ~16 周期 →
 *       完成: ADC_FLAG 置位, ADC_START 清除, 结果写入 RES/RESL。
 *
 * 预期 (dump-ram, 500 周期):
 *   SFR:0xBC = 0xA0   (POWER + FLAG, START 已清)
 *   SFR:0xBD = 0xC0   (ADC_RES = 0x300>>2 = 0xC0, 通道 0 固定电压)
 *   SFR:0xBE = 0x00   (ADC_RESL 低 2 位为 0)
 */
typedef unsigned char u8;

sfr ADC_CONTR = 0xBC;
sfr ADC_RES   = 0xBD;
sfr ADC_RESL  = 0xBE;

void main(void)
{
	ADC_CONTR = 0x80;       /* ADC_POWER = 1 */
	ADC_CONTR = 0xC0;       /* + ADC_START = 1 (启动转换) */
	for (;;) {
		/* 挂起: 让转换完成置 FLAG */
	}
}
