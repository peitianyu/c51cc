/* 23_func_recursive: 递归函数 */

int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main(void) {
    int r = 0;
    r = r + factorial(5);    /* 120 */
    r = r + fibonacci(7);    /* 13 */
    return r;                 /* 133 */
}
