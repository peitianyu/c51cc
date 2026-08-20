/* 105_long_div: 32 位除法/取模 (硬件测试, 返回 0=通过)
 * 覆盖: 有符号/无符号 32 位 DIV/MOD, C99 截断向零, 余数符号随被除数。 */
long g_a, g_b;

int main(void) {
    g_a = 900000L; g_b = 300L;
    long q = g_a / g_b;              /* 3000 */
    long m = g_a % g_b;              /* 0 */
    if (q != 3000L) return 1;
    if (m != 0L) return 2;

    /* 有符号: 被除数负 */
    g_a = -900000L; g_b = 300L;
    q = g_a / g_b;                   /* -3000 */
    m = g_a % g_b;                   /* 0 */
    if (q != -3000L) return 3;
    if (m != 0L) return 4;

    /* 有符号: 除数负 */
    g_a = 900000L; g_b = -300L;
    q = g_a / g_b;                   /* -3000 */
    m = g_a % g_b;                   /* 0 */
    if (q != -3000L) return 5;
    if (m != 0L) return 6;

    /* 两者负 */
    g_a = -900000L; g_b = -300L;
    q = g_a / g_b;
    if (q != 3000L) return 7;

    /* 余数符号随被除数 (截断向零): -900001 / 300 = -3000 余 -1 */
    g_a = -900001L; g_b = 300L;
    q = g_a / g_b;
    m = g_a % g_b;
    if (q != -3000L) return 8;
    if (m != -1L) return 9;

    /* 被除数为 0 */
    g_a = 0L; g_b = 12345L;
    q = g_a / g_b;
    if (q != 0L) return 10;
    m = g_a % g_b;
    if (m != 0L) return 11;

    /* 除数为 1 / -1 */
    g_a = 12345678L; g_b = 1L;
    if ((g_a / g_b) != 12345678L) return 12;
    g_b = -1L;
    if ((g_a / g_b) != -12345678L) return 13;

    /* 无符号: 高位置位 */
    {
        unsigned long ua = 0x80000000UL, ub = 3UL;
        unsigned long uq = ua / ub;      /* 0x2AAAAAAA = 715827882 */
        unsigned long um = ua % ub;      /* 2 */
        if (uq != 715827882UL) return 14;
        if (um != 2UL) return 15;
        ua = 0xFFFFFFFFUL; ub = 0x10000UL;
        uq = ua / ub;                    /* 65535 */
        um = ua % ub;                    /* 0xFFFF */
        if (uq != 65535UL) return 16;
        if (um != 65535UL) return 17;
    }

    return 0;
}
