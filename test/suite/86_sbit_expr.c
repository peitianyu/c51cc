/* 86_sbit_expr: sbit 与布尔表达式组合 (硬件测试, 返回 0=通过)
 * STC32G 常见模式: sbit |= 运算结果, 多 sbit 逻辑表达式, sbit 与变量混用。
 */
typedef unsigned char u8;

sfr P1 = 0x90;
sbit P1_0 = P1 ^ 0;
sbit P1_1 = P1 ^ 1;
sbit P1_2 = P1 ^ 2;
sbit P1_3 = P1 ^ 3;

int main(void) {
    u8 x = 1, y = 0;

    /* sbit = 变量值 */
    P1_0 = x;
    if (!P1_0) return 1;
    P1_0 = 0;
    if (P1_0) return 2;

    /* sbit = 表达式 */
    P1_1 = (x && y);
    if (P1_1) return 3;
    P1_1 = (x || y);
    if (!P1_1) return 4;

    /* sbit = 位运算结果 */
    P1_2 = (P1_1 ^ 1);
    if (P1_2) return 5;

    /* 多 sbit 逻辑 */
    P1_3 = (P1_1 && !P1_2);
    if (!P1_3) return 6;
    P1_3 = (P1_0 || P1_2);
    if (P1_3) return 7;

    /* sbit 条件分支 */
    P1_0 = 1;
    if (P1_0) { P1_2 = 0; } else { P1_2 = 1; }
    if (P1_2) return 8;

    return 0;
}
