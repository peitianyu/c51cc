/* 74_gpio_modes: GPIO 模式寄存器配置 (硬件测试, 返回 0=通过)
 * 覆盖: P0M0/P0M1/P1M0/P1M1 准双向/推挽/高阻/开漏 模式写读回。
 */
typedef unsigned char u8;

sfr P0M0 = 0x94;  sfr P0M1 = 0x93;
sfr P1M0 = 0x92;  sfr P1M1 = 0x91;

int main(void) {
    /* 准双向 (00) */
    P0M0 = 0x00;  P0M1 = 0x00;
    if (P0M0 != 0x00 || P0M1 != 0x00) return 1;
    /* 推挽 (PxM0=1, PxM1=0) */
    P0M0 = 0x01;  P0M1 = 0x00;
    if (P0M0 != 0x01 || P0M1 != 0x00) return 2;
    /* 高阻输入 (PxM0=0, PxM1=1) */
    P1M0 = 0x00;  P1M1 = 0x80;
    if (P1M0 != 0x00 || P1M1 != 0x80) return 3;
    /* 开漏 (PxM0=1, PxM1=1) */
    P1M0 = 0xFF;  P1M1 = 0xFF;
    if (P1M0 != 0xFF || P1M1 != 0xFF) return 4;
    return 0;
}
