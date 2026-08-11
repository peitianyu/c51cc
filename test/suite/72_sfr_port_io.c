/* 72_sfr_port_io: SFR 端口读写回 (硬件测试, 返回 0=通过)
 * 覆盖: P0-P3 端口直接赋值 + 读回, 全 0/全 1/特定值。
 */
typedef unsigned char u8;

sfr P0 = 0x80;  sfr P1 = 0x90;  sfr P2 = 0xA0;  sfr P3 = 0xB0;

int main(void) {
    P0 = 0x5A;  if (P0 != 0x5A) return 1;
    P1 = 0xA5;  if (P1 != 0xA5) return 2;
    P2 = 0x0F;  if (P2 != 0x0F) return 3;
    P3 = 0xF0;  if (P3 != 0xF0) return 4;
    P0 = 0x00;  if (P0 != 0x00) return 5;
    P1 = 0xFF;  if (P1 != 0xFF) return 6;
    return 0;
}
