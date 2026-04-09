/* 44_complex_expr: 复杂表达式 */

int main(void) {
    int a = 5;
    int b = 3;
    int c = 2;

    /* 混合运算 */
    int r1 = (a + b) * c - (a - b) / c;  /* 8*2 - 2/2 = 16-1 = 15 */
    int r2 = a * b + c * (a - b);          /* 15 + 2*2 = 19 */
    int r3 = (a & 0xF) | (b << 2);        /* 5 | 12 = 13 */
    int r4 = (a > b) + (b < c) + (a == 5); /* 1+0+1 = 2 */

    return r1 + r2 + r3 + r4;  /* 15+19+13+2 = 49 */
}
