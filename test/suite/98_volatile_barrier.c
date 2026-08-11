/* 98_volatile_barrier: volatile 写屏障与 SFR 顺序 (硬件测试, 返回 0=通过) */
sfr P1 = 0x90;
volatile unsigned char flag = 0;
int main(void) {
    P1 = 0;
    flag = 1;  /* volatile 写 — 编译器必须在 P1 访问前完成 */
    P1 = 0xAA;
    if (!flag) return 1;
    if (P1 != 0xAA) return 2;
    /* 验证 volatile 读回被尊重 */
    flag = 0;
    if (flag) return 3;
    return 0;
}
