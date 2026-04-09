/* 11_cmp_lt_gt: 比较运算 < > <= >= (unsigned) */

int main(void) {
    int a = 10;
    int b = 20;
    int r = 0;
    if (a < b)  r = r + 1;    /* +1 */
    if (b > a)  r = r + 2;    /* +2 */
    if (a <= b) r = r + 4;    /* +4 */
    if (b >= a) r = r + 8;    /* +8 */
    if (a <= a) r = r + 16;   /* +16 */
    if (a >= a) r = r + 32;   /* +32 */
    if (a > b)  r = r + 64;   /* skip */
    if (b < a)  r = r + 128;  /* skip */
    return r;                   /* 63 */
}
