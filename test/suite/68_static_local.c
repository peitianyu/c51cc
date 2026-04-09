/* 68_static_local: 静态局部变量 */

int counter(void) {
    static int cnt = 0;
    cnt = cnt + 1;
    return cnt;
}

int main(void) {
    int a = counter();  /* 1 */
    int b = counter();  /* 2 */
    int c = counter();  /* 3 */
    return a + b + c;   /* 6 */
}
