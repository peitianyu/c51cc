/* 73_sbit_bit_ops: sbit/bit 位操作 (硬件测试, 返回 0=通过)
 * 覆盖: sbit 置位/清除/翻转/判断, bit 变量赋值/翻转, 复合位运算。
 */
typedef unsigned char u8;

sfr P1 = 0x90;
sbit P1_0 = P1 ^ 0;
sbit P1_1 = P1 ^ 1;
sbit P1_2 = P1 ^ 2;
sbit P1_7 = P1 ^ 7;
bit g_bit0 = 0;
bit g_bit1 = 1;

int main(void) {
    /* sbit 置位/清除 */
    P1_0 = 1;  if (!P1_0) return 1;
    P1_0 = 0;  if (P1_0)  return 2;
    /* 翻转 */
    P1_1 = 1;  if (P1_1 != 1) return 3;
    P1_1 = !P1_1;  if (P1_1) return 4;
    P1_1 = !P1_1;  if (!P1_1) return 5;
    P1_1 = !P1_1;  /* 翻回 0 (1→0→1→0), 供下方组合 (P1_0|P1_1) 期望 0 */
    /* 高位 sbit */
    P1_7 = 1;  if (!P1_7) return 6;
    P1_7 = 0;  if (P1_7)  return 7;
    /* bit 变量 */
    g_bit0 = 1;  if (!g_bit0) return 8;
    g_bit0 = 0;  if (g_bit0)  return 9;
    g_bit1 = 0;  if (g_bit1)  return 10;
    g_bit1 = !g_bit1;  if (!g_bit1) return 11;
    /* sbit 与普通值组合 */
    P1_2 = (P1_0 | P1_1);
    if (P1_2) return 12;
    P1_0 = 1;
    P1_2 = P1_0;
    if (!P1_2) return 13;
    return 0;
}
