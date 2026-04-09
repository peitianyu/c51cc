/* 25_ptr_basic: 基础指针操作 */

int main(void) {
    int x = 42;
    int *p = &x;
    int y = *p;      /* y = 42 */
    *p = 100;        /* x = 100 */
    return x + y;    /* 100 + 42 = 142 */
}
