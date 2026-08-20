/* 107_long_shift: 32 位移位 (硬件测试, 返回 0=通过)
 * 覆盖: SLL/SRL/SRA 32 位, 各种移位量, 有符号算术右移。 */
long g;

int main(void) {
    g = 1L;
    long l1 = g << 4;                 /* 16 */
    if (l1 != 16L) return 1;
    long l2 = g << 16;                /* 0x10000 */
    if (l2 != 0x10000L) return 2;
    long l3 = g << 31;                /* 0x80000000 (有符号 = 负) */
    if (l3 != 0x80000000L) return 3;  /* 与 unsigned long 常量比较 */
    if (l3 != -2147483648L) return 4;

    /* 算术右移 (有符号) */
    g = -8L;
    if ((g >> 1) != -4L) return 5;
    if ((g >> 2) != -2L) return 6;
    g = 0x80000000L;                  /* 负 */
    if ((g >> 31) != -1L) return 7;   /* 符号扩展 */

    /* 逻辑右移 (无符号) */
    {
        unsigned long u = 0x80000000UL;
        if ((u >> 31) != 1UL) return 8;
        if ((u >> 16) != 0x8000UL) return 9;
        if ((u << 1) != 0UL) return 10;   /* 移出 32 位 */
        u = 0x00010000UL;
        if ((u >> 16) != 1UL) return 11;
        if ((u << 16) != 0x10000000UL) return 12;
    }

    /* 移位量 ≥ 32 → 0 (逻辑) / 饱和 (算术) */
    g = 0x12345678L;
    if ((g >> 32) != 0L) return 13;   /* UB, 但常见实现 = 0; 逻辑移位 */
    if ((g << 32) != 0L) return 14;

    /* 正数算术右移 */
    g = 0x12345678L;
    if ((g >> 8) != 0x00123456L) return 15;
    if ((g >> 16) != 0x1234L) return 16;

    return 0;
}
