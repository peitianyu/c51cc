/* 87_idata: idata 内部 RAM 直接寻址 (硬件测试, 返回 0=通过) */
idata unsigned char ibuf = 0;
idata unsigned char iarr[4];
int main(void) {
    ibuf = 0x99;  if (ibuf != 0x99) return 1;
    iarr[0]=0x11; iarr[1]=0x22; iarr[2]=0x33; iarr[3]=0x44;
    if (iarr[0] != 0x11) return 2;
    if (iarr[2] != 0x33) return 3;
    ibuf = iarr[3];  if (ibuf != 0x44) return 4;
    return 0;
}
