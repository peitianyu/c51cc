/* 49_func_ptr: 函数指针 */

int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }

int apply(int (*op)(int, int), int x, int y) {
    return op(x, y);
}

int main(void) {
    int (*fp)(int, int) = add;
    int r = fp(3, 4);           /* 7 */
    fp = mul;
    r = r + fp(5, 6);           /* 7+30 = 37 */
    r = r + apply(add, 10, 20); /* 37+30 = 67 */
    return r;
}
