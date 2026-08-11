/* 84_volatile_sfr_cmp: volatile SFR 复合运算 (硬件测试, 返回 0=通过)
 * STC32G 常见 GPIO 模式: P0 |= 0x40 (SETB 等效), P1 &= ~0x02, etc。
 * 覆盖: volatile |= / &=~ / ^= 读写回。
 */
typedef unsigned char u8;

sfr P0 = 0x80;  sfr P1 = 0x90;  sfr P2 = 0xA0;

int main(void) {
    /* |= 置位 */
    P0 = 0x00;  P0 |= 0x0F;  if (P0 != 0x0F) return 1;
    P0 |= 0x30;              if (P0 != 0x3F) return 2;

    /* &=~ 清除 */
    P1 = 0xFF;  P1 &= ~0x03; if (P1 != 0xFC) return 3;
    P1 &= ~0xC0;             if (P1 != 0x3C) return 4;

    /* ^= 翻转 */
    P2 = 0x55;  P2 ^= 0x0F;  if (P2 != 0x5A) return 5;
    P2 ^= 0xFF;              if (P2 != 0xA5) return 6;

    /* 组合: 读-修改-写链 */
    P0 = 0x01;  P0 = (P0 | 0x02) & 0x7F;  if (P0 != 0x03) return 7;
    P0 = P0 ^ 0x03;                       if (P0 != 0x00) return 8;

    return 0;
}
