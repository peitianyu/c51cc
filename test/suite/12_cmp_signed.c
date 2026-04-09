/* 12_cmp_signed: 有符号数比较 */

int main(void) {
    int a = -5;
    int b = 3;
    int c = -10;
    int r = 0;
    if (a < b)  r = r + 1;    /* +1: -5 < 3 */
    if (c < a)  r = r + 2;    /* +2: -10 < -5 */
    if (b > a)  r = r + 4;    /* +4: 3 > -5 */
    if (a > c)  r = r + 8;    /* +8: -5 > -10 */
    if (a <= a) r = r + 16;   /* +16 */
    if (a >= a) r = r + 32;   /* +32 */
    return r;                   /* 63 */
}
