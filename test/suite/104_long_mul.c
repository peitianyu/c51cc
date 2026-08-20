/* 104_long_mul: 32 位乘法 (硬件测试, 返回 0=通过)
 * 覆盖: long×long 运行时乘法, 结果取低 32 位。 */
long g_a, g_b;

int main(void) {
    g_a = 70000L; g_b = 60000L;
    long p = g_a * g_b;              /* 4200000000 → 低 32 位 0xFA56EA00 = -94967296 */
    if (p != -94967296L) return 1;
    if (p != 0xFA56EA00L) return 2;  /* unsigned long 视角 */

    g_a = 12345L; g_b = 67890L;
    p = g_a * g_b;                   /* 838102050 = 0x31F1F622 */
    if (p != 838102050L) return 3;

    g_a = -12345L; g_b = 67890L;     /* 有符号乘 */
    p = g_a * g_b;                   /* -838102050 */
    if (p != -838102050L) return 4;

    g_a = -12345L; g_b = -67890L;
    p = g_a * g_b;
    if (p != 838102050L) return 5;

    /* 16 位 × 16 位 (高字为 0) */
    g_a = 300L; g_b = 400L;
    p = g_a * g_b;
    if (p != 120000L) return 6;

    /* 高字参与: 0x10000 × 2 = 0x20000 */
    g_a = 65536L; g_b = 2L;
    p = g_a * g_b;
    if (p != 131072L) return 7;

    return 0;
}
