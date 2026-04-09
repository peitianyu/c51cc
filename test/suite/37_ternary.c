/* 37_ternary: 三元运算符 */

int max(int a, int b) {
    return (a > b) ? a : b;
}

int min(int a, int b) {
    return (a < b) ? a : b;
}

int main(void) {
    int r = 0;
    r = r + max(10, 20);   /* 20 */
    r = r + min(10, 20);   /* 10 */
    r = r + max(-5, 3);    /* 3 */
    return r;               /* 33 */
}
