/* 106_long_cmp: 32 位比较 (硬件测试, 返回 0=通过)
 * 覆盖: EQ/NE/LT/GT/LE/GE 有符号/无符号, 高字参与比较。 */
long g_a, g_b;

int main(void) {
    g_a = 0x12345678L; g_b = 0x12345677L;
    if (!(g_a > g_b)) return 1;       /* 305419896 > 305419895 */
    if (!(g_b < g_a)) return 2;
    if (!(g_a >= g_a)) return 3;
    if (!(g_a == 0x12345678L)) return 4;
    if (g_a != 0x12345678L) return 5;
    if (g_a <= g_b) return 6;
    if (g_a == g_b) return 7;

    /* 高字不同的比较: 0x00010000 vs 0x0000FFFF */
    g_a = 0x00010000L; g_b = 0x0000FFFFL;
    if (!(g_a > g_b)) return 8;
    if (g_a < g_b) return 9;
    if (!(g_b < g_a)) return 10;

    /* 负数有符号比较 */
    g_a = -5L; g_b = -3L;
    if (!(g_a < g_b)) return 11;      /* -5 < -3 */
    if (g_a > g_b) return 12;
    if (!(g_a != g_b)) return 13;
    g_a = -3L;
    if (!(g_a == g_b)) return 14;
    if (!(g_a >= g_b)) return 15;
    if (g_a < g_b) return 16;

    /* 正负混合 */
    g_a = -1L; g_b = 0L;
    if (!(g_a < g_b)) return 17;
    if (!(g_b > g_a)) return 18;
    g_b = 1L;
    if (!(g_a < g_b)) return 19;

    /* 无符号 32 位: 高位置位应比小正数大 */
    {
        unsigned long ua = 0x80000000UL, ub = 1UL;
        if (!(ua > ub)) return 20;
        if (ua < ub) return 21;
        if (!(ub < ua)) return 22;
        if (!(ua != ub)) return 23;
        if (ua == ub) return 24;
        unsigned long uc = 0x80000001UL;
        if (!(ua < uc)) return 25;
        if (!(uc > ua)) return 26;
        if (!(ua <= ua)) return 27;
        if (ua > ua) return 28;
    }

    return 0;
}
