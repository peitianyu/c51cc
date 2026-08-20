/* 109_long_param: long 参数与返回 (硬件测试, 返回 0=通过)
 * 覆盖: 32 位 ABI 参数传递 (DR4/DR0), long 返回值, 多参数混合。 */
long g_a, g_b, g_c;

long add3(long a, long b, long c) { return a + b + c; }
long sub2(long a, long b) { return a - b; }
long mul2(long a, long b) { return a * b; }
long ident(long x) { return x; }

int main(void) {
    g_a = 100000L; g_b = 200000L; g_c = 300000L;
    long r = add3(g_a, g_b, g_c);     /* 600000 */
    if (r != 600000L) return 1;

    r = sub2(500000L, 700000L);       /* -200000 (常量实参可能被内联折叠) */
    if (r != -200000L) return 2;

    r = sub2(g_b, g_a);               /* 100000 */
    if (r != 100000L) return 3;

    r = mul2(g_b, g_c);               /* 60000000000 → 低 32 位 */
    /* 60000000000 = 0xDF8475800 → 低 32 位 0xF8475800 = -130862080 */
    if (r != -130862080L) return 4;

    r = ident(g_a);
    if (r != 100000L) return 5;
    r = ident(-5L);
    if (r != -5L) return 6;

    /* 混合: long + int 参数 */
    r = add3(g_a, 1L, g_c);
    if (r != 400001L) return 7;

    /* 返回负数 */
    r = sub2(g_a, g_c);               /* -200000 */
    if (r != -200000L) return 8;

    return 0;
}
