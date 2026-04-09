/* 61_gcd_lcm: 最大公约数和最小公倍数 (综合测试) */

int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

int main(void) {
    int r = 0;
    r = r + gcd(12, 8);    /* 4 */
    r = r + gcd(15, 10);   /* 5 */
    r = r + gcd(7, 13);    /* 1 */
    return r;                /* 10 */
}
