/* 97_sfr_mask_write: SFR 掩码写 (|= / &= 模式) (硬件测试, 返回 0=通过) */
sfr P1 = 0x90; sfr P3 = 0xB0;
int main(void) {
    /* 常量掩码 &= ~ (清除位) */
    P1 = 0xFF;  P1 &= ~0x0F;   if (P1 != 0xF0) return 1;
    P1 = 0xFF;  P1 &= ~0x55;   if (P1 != 0xAA) return 2;
    /* 常量掩码 |= (置位) */
    P3 = 0;     P3 |= 0x55;    if (P3 != 0x55) return 3;
    /* 常量掩码 &= (保留位) */
    P3 &= 0x0F;                if (P3 != 0x05) return 4;
    /* ^= 翻转 */
    P1 = 0x0F;  P1 ^= 0xFF;   if (P1 != 0xF0) return 5;
    return 0;
}
