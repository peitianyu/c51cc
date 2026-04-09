/* 46_signed_shift: 有符号移位 */

int main(void) {
    int a = -16;
    int b = a >> 1;   /* 算术右移: -8 */
    int c = a >> 2;   /* 算术右移: -4 */

    int d = 1;
    int e = d << 8;   /* 256 */

    return b + c + e;  /* -8 + (-4) + 256 = 244 */
}
