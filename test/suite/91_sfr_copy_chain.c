/* 91_sfr_copy_chain: SFR 间赋值链 (硬件测试, 返回 0=通过) */
sfr P0 = 0x80; sfr P1 = 0x90; sfr P2 = 0xA0; sfr P3 = 0xB0;
int main(void) {
    P0 = 0xAA; P1 = P0; P2 = P1; P3 = P2;
    if (P1 != 0xAA) return 1;
    if (P2 != 0xAA) return 2;
    if (P3 != 0xAA) return 3;
    P0 = P3;  if (P0 != 0xAA) return 4;
    return 0;
}
