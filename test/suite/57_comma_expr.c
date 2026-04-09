/* 57_multi_assign: 多重赋值 */

int main(void) {
    int a;
    int b;
    int c;
    a = 3;
    b = a + 1;   /* 4 */
    c = a + b;   /* 7 */
    return a + b + c;  /* 3 + 4 + 7 = 14 */
}
