/* 92_volatile_loop_sfr: volatile SFR 循环读 (硬件测试, 返回 0=通过) */
sfr P1 = 0x90;
volatile unsigned char vflag = 0;
int main(void) {
    unsigned char i, sum = 0;
    P1 = 0x55;
    for (i = 0; i < 4; i++) {
        sum += P1;
        vflag = 1;  /* volatile 屏障: 禁止编译器跨循环缓存 P1 */
    }
    if (sum != 0x55 * 4) return 1;
    if (!vflag) return 2;
    return 0;
}
