/* 111_ulong_ops: unsigned long 运算 (硬件测试, 返回 0=通过)
 * 覆盖: 0x80000000+ 字面量, 无符号 32 位算术/移位/比较。 */
unsigned long g_u;

int main(void) {
    g_u = 0xFFFFFFFFUL;
    if (g_u != 0xFFFFFFFFUL) return 1;
    if (g_u != 4294967295UL) return 2;
    if (g_u == 0xFFFFFFFFUL - 1UL) return 3;

    g_u = 0x80000000UL;
    if (g_u != 2147483648UL) return 4;

    /* 无符号算术 */
    {
        unsigned long a = 0x80000000UL, b = 3UL;
        unsigned long s = a + b;          /* 0x80000003 */
        if (s != 0x80000003UL) return 5;
        unsigned long d = a - b;          /* 0x7FFFFFFD */
        if (d != 0x7FFFFFFDUL) return 6;
        if (a + a != 0UL) return 7;       /* 溢出回绕 */
        if (a - a != 0UL) return 8;

        unsigned long q = a / b;          /* 0x2AAAAAAA = 715827882 */
        if (q != 715827882UL) return 9;
        unsigned long m = a % b;          /* 2 */
        if (m != 2UL) return 10;
    }

    /* 无符号逻辑 */
    {
        unsigned long a = 0xFFFFFFFFUL;
        if ((a & 0x0000FFFFUL) != 0xFFFFUL) return 11;
        if ((a | 0UL) != 0xFFFFFFFFUL) return 12;
        if ((a ^ 0xFFFFFFFFUL) != 0UL) return 13;
        if ((~a) != 0UL) return 14;
    }

    /* 无符号移位 */
    {
        unsigned long a = 0x80000000UL;
        if ((a >> 31) != 1UL) return 15;
        if ((a >> 16) != 0x8000UL) return 16;
        if ((a << 1) != 0UL) return 17;
        unsigned long b = 0x12345678UL;
        if ((b >> 16) != 0x1234UL) return 18;
        if ((b << 16) != 0x56780000UL) return 19;
    }

    /* 无符号比较 (高字判定) */
    {
        unsigned long a = 0x80000000UL, b = 0x7FFFFFFFUL;
        if (!(a > b)) return 20;
        if (a < b) return 21;
        if (!(b < a)) return 22;
        if (!(a >= b)) return 23;
    }

    return 0;
}
