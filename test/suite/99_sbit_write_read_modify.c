/* 99_sbit_write_read_modify: sbit 写-读-修改 全模式 (硬件测试, 返回 0=通过) */
sfr P2 = 0xA0;
sbit P2_0 = P2 ^ 0;  sbit P2_1 = P2 ^ 1;
sbit P2_6 = P2 ^ 6;  sbit P2_7 = P2 ^ 7;
int main(void) {
    P2 = 0;
    P2_0 = 1;  if (!P2_0 || P2_0 != 1) return 1;
    P2_7 = 1;  if (!P2_7) return 2;
    /* 读-修改-写: SETB 后 CLR */
    P2_0 = 0;  if (P2_0) return 3;
    /* 高位 sbit 翻转 */
    P2_6 = 1; P2_6 = !P2_6;  if (P2_6) return 4;
    P2_6 = !P2_6;  if (!P2_6) return 5;
    /* 两 sbit 互拷 */
    P2_0 = 1; P2_6 = 0;
    P2_1 = P2_0;  if (!P2_1) return 6;
    P2_1 = P2_6;  if (P2_1) return 7;
    return 0;
}
