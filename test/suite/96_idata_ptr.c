/* 96_idata_ptr: idata 指针间接访问 (硬件测试, 返回 0=通过) */
idata unsigned char ibuf = 0;
idata unsigned char iarr[3];
int main(void) {
    unsigned char *p;
    iarr[0]=0x11; iarr[1]=0x22; iarr[2]=0x33;
    p = iarr;      if (*p != 0x11) return 1;
    p = iarr+1;    if (*p != 0x22) return 2;
    p = &ibuf; *p = 0x99;
    if (ibuf != 0x99) return 3;
    return 0;
}
