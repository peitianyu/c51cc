/* 58_sizeof: sizeof运算符 */

struct S {
    int a;
    int b;
    char c;
};

int main(void) {
    int r = 0;
    r = r + sizeof(char);     /* 1 */
    r = r + sizeof(int);      /* 2 (8051 int is 16-bit) */
    r = r + sizeof(int *);    /* 指针大小 (2 or 3) */
    r = r + sizeof(struct S); /* 结构体大小 */
    return r;
}
