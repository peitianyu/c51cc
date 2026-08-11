/* 95_sfr_math: SFR 算术表达式读 (硬件测试, 返回 0=通过) */
sfr P0 = 0x80; sfr P1 = 0x90;
int main(void) {
    P0 = 0x10; P1 = 0x20;
    if (P0 + P1 != 0x30) return 1;
    if (P1 - P0 != 0x10) return 2;
    P0 = P1 + 0x05; if (P0 != 0x25) return 3;
    return 0;
}
