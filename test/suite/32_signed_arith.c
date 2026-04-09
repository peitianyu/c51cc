/* 32_signed_arith: signed int 运算 */

int main(void) {
    int a = -100;
    int b = 50;
    int c = a + b;    /* -50 */
    int d = a - b;    /* -150 */
    int e = a * 2;    /* -200 */
    int f = a / 2;    /* -50 */
    return c + d + e + f;  /* -50 + (-150) + (-200) + (-50) = -450 */
}
