/* 103_long_basic: long 基本运算 — 全局/局部/常量/加减/取反/负 (硬件测试, 返回 0=通过)
 * 覆盖: 32 位 load/store、32 位常量、ADD/SUB、NEG、NOT。 */
long g_a, g_b;

int main(void) {
    g_a = 70000L;               /* 0x11170, 32 位正 */
    g_b = 60000L;
    if (g_a != 70000L) return 1;
    if (g_b != 60000L) return 2;

    long s = g_a + g_b;         /* 130000 = 0x1FBD0, 低 16 位进位到高字 */
    if (s != 130000L) return 3;
    if (s != 0x1FBD0L) return 4;

    long d = g_a - g_b;         /* 10000 */
    if (d != 10000L) return 5;

    long neg = -g_a;            /* -70000 = 0xFFFEE890 */
    if (neg != -70000L) return 6;

    long notv = ~g_a;           /* ~0x00011170 = 0xFFFEEE8F */
    if (notv != 0xFFFEEE8FL) return 7;
    if (notv != ~70000L) return 8;

    /* 局部 long 与 32 位常量 */
    long x = 0x12345678L;
    if (x != 0x12345678L) return 9;
    if (x != 305419896L) return 10;
    if ((x + 1L) != 0x12345679L) return 11;

    /* 16 位加法不影响高字 */
    long y = 0x00010000L;
    long z = y + 1L;
    if (z != 0x00010001L) return 12;
    if (z - y != 1L) return 13;

    return 0;
}
