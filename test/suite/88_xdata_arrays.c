/* 88_xdata_arrays: xdata 外部 RAM 数组 (硬件测试, 返回 0=通过) */
typedef unsigned char u8;
u8 xdata buf = 0;
u8 xdata arr[4];
int main(void) {
    buf = 0x55;  if (buf != 0x55) return 1;
    arr[0]=0xAA; arr[1]=0xBB; arr[2]=0xCC; arr[3]=0xDD;
    if (arr[0] != 0xAA) return 2;
    if (arr[3] != 0xDD) return 3;
    buf = arr[1];  if (buf != 0xBB) return 4;
    return 0;
}
