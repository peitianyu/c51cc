/* 47_mixed_types: 混合类型运算 (char/int/unsigned) */

int main(void) {
    char a = -10;
    unsigned char b = 200;
    int c = 1000;
    unsigned int d = 50000;

    int r1 = a + c;        /* -10 + 1000 = 990 */
    int r2 = b + 56;       /* 200 + 56 = 256 */

    return r1 + r2;        /* 990 + 256 = 1246 */
}
