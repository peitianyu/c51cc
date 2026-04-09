/* 45_signed_div_mod: 有符号除法和取模 */

int main(void) {
    int a = -17;
    int b = 5;
    int q = a / b;    /* -3 (truncation toward zero) */
    int r = a % b;    /* -2 */
    
    int c = 17;
    int d = -5;
    int q2 = c / d;   /* -3 */
    int r2 = c % d;   /* 2 */

    return q + r + q2 + r2;  /* -3 + (-2) + (-3) + 2 = -6 */
}
