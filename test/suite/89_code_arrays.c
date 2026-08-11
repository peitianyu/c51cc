/* 89_code_arrays: code ROM 数组常量 (硬件测试, 返回 0=通过) */
unsigned char code val = 0xAB;
unsigned char code tbl[3] = {0xDE, 0xAD, 0xBE};
int main(void) {
    if (val != 0xAB) return 1;
    if (tbl[0] != 0xDE) return 2;
    if (tbl[2] != 0xBE) return 3;
    return 0;
}
