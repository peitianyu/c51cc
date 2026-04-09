/* 62_power: 快速幂 (综合测试: 递归/乘法/条件) */

int power(int base, int exp) {
    if (exp == 0) return 1;
    if (exp == 1) return base;
    int half = power(base, exp / 2);
    if (exp % 2 == 0) {
        return half * half;
    } else {
        return half * half * base;
    }
}

int main(void) {
    int r = 0;
    r = r + power(2, 0);    /* 1 */
    r = r + power(2, 5);    /* 32 */
    r = r + power(3, 3);    /* 27 */
    return r;                 /* 60 */
}
