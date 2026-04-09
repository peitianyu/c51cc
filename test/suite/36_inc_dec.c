/* 36_inc_dec: 自增自减 (前缀/后缀) */

int main(void) {
    int a = 10;
    int b;
    int r = 0;

    b = a++;   /* b=10, a=11 */
    r = r + b; /* r=10 */

    b = a--;   /* b=11, a=10 */
    r = r + b; /* r=21 */

    b = ++a;   /* a=11, b=11 */
    r = r + b; /* r=32 */

    b = --a;   /* a=10, b=10 */
    r = r + b; /* r=42 */

    return r;  /* 42 */
}
