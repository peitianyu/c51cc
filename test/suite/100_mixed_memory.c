/* 100_mixed_memory: 混合内存空间综合测试 (硬件测试, 返回 0=通过)
 * 覆盖: data/idata/xdata/code + sfr/sbit 混在单函数中。
 */
sfr P0 = 0x80;  sfr P1 = 0x90;
sbit P1_0 = P1 ^ 0;
idata unsigned char ib = 0;
xdata unsigned char xb = 0;
code unsigned char cv = 0xEE;

int main(void) {
    /* idata 写 + xdata 读回 */
    ib = 0x11;  if (ib != 0x11) return 1;
    xb = 0x22;  if (xb != 0x22) return 2;
    /* code 段读 */
    if (cv != 0xEE) return 3;
    /* SFR 交互 */
    P0 = ib;    if (P0 != 0x11) return 4;
    P0 = xb;    if (P0 != 0x22) return 5;
    /* sbit 操作 */
    P1 = 0;  P1_0 = 1;  if (P1 != 0x01) return 6;
    /* 跨空间赋值 (xdata → idata) */
    ib = xb;  if (ib != 0x22) return 7;
    return 0;
}
