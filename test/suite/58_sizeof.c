/* 58_sizeof: sizeof运算符 — C251 int=16 位, 指针 2 字节 (near), GCC 32 位差分会错 */
/* EXPECT 10 */
/* 注意: c51cc 用 2 字节 near 指针 (设计差异), 非 Keil/SDCC 通用指针 3 字节。
 * 参见 docs/c51cc-vs-sdcc-bug-report.md §6b/§7.3。 */

struct S {
    int a;
    int b;
    char c;
};

int main(void) {
    int r = 0;
    r = r + sizeof(char);     /* 1 */
    r = r + sizeof(int);      /* 2 (8051 int is 16-bit) */
    r = r + sizeof(int *);    /* 2 (c51cc near 指针 2 字节, 非 Keil 通用指针 3 字节) */
    r = r + sizeof(struct S); /* 5 (int a + int b + char c, 无填充) */
    return r;
}
