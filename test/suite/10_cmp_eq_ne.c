/* 10_cmp_eq_ne: 比较运算 == != */

int main(void) {
    int a = 5;
    int b = 5;
    int c = 3;
    int r = 0;
    if (a == b) r = r + 1;   /* +1 */
    if (a != c) r = r + 2;   /* +2 */
    if (a == c) r = r + 4;   /* skip */
    if (a != b) r = r + 8;   /* skip */
    return r;                  /* 3 */
}
