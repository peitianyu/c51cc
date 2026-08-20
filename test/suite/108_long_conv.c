/* 108_long_conv: 宽度转换与 32 位常量 (硬件测试, 返回 0=通过)
 * 覆盖: int→long (SEXT/ZEXT), long→int (TRUNC), 大 32 位常量。 */
int g_i;
unsigned int g_ui;
long g_l;

int main(void) {
    /* int → long 符号扩展 */
    g_i = 30000;
    g_l = g_i;
    if (g_l != 30000L) return 1;
    g_i = -30000;
    g_l = g_i;
    if (g_l != -30000L) return 2;

    /* unsigned int → long 零扩展 */
    g_ui = 60000;
    g_l = g_ui;
    if (g_l != 60000L) return 3;

    /* long → int 截断 (低 16 位) */
    g_l = 0x12345678L;
    {
        int back = (int)g_l;
        if (back != 0x5678) return 4;
        if (back != 22136) return 5;
    }

    /* 大 32 位常量 */
    g_l = 0x80000000L;                /* 有符号 long = INT32_MIN */
    if (g_l != -2147483648L) return 6;
    if (g_l != 0x80000000L) return 7;
    g_l = 0xFFFFFFFFL;                /* -1 */
    if (g_l != -1L) return 8;
    if (g_l != 0xFFFFFFFFL) return 9;
    g_l = 305419896L;                 /* 0x12345678 十进制 */
    if (g_l != 0x12345678L) return 10;
    g_l = -123456789L;
    if (g_l != -123456789L) return 11;
    if (g_l != 0xF8A432EBL) return 12;

    /* int 常量参与 long 运算 (提升) */
    g_i = 1000;
    g_l = g_i + 400000000L;           /* 400001000 */
    if (g_l != 400001000L) return 13;
    if (g_l != 0x17D784E8L) return 14;

    /* long 常量 → int 截断语义 (赋值) */
    g_l = 0x12345678L;
    g_i = (int)g_l;
    if (g_i != 0x5678) return 15;

    return 0;
}
