/* 59_cast_explicit: 显式类型转换 */

int main(void) {
    int a = 300;
    char b = (char)a;          /* 300 & 0xFF = 44 */
    int c = (int)b;            /* 44 (或sign-extend如果char有符号) */
    unsigned int d = 50000;
    int e = (int)d;            /* 取决于值 */
    unsigned char f = (unsigned char)(-1);  /* 255 */
    return b + f;              /* 44 + 255 = 299 (如果b是unsigned) */
}
