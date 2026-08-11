/* 94_sfr_sbit_combo: sfr + sbit 组合操作 (硬件测试, 返回 0=通过) */
sfr P1 = 0x90;
sbit P1_0 = P1 ^ 0;
sbit P1_7 = P1 ^ 7;
int main(void) {
    P1 = 0;
    P1_0 = 1;  if (P1 != 0x01) return 1;
    P1_7 = 1;  if (P1 != 0x81) return 2;
    P1 = 0xFF; /* 全 1 */
    P1_0 = 0;  if (P1 != 0xFE) return 3;
    P1_7 = 0;  if (P1 != 0x7E) return 4;
    /* sbit 读影响 P1 整体读写 */
    P1_0 = 1; P1_7 = 1; if (P1 != 0xFF) return 5;
    return 0;
}
