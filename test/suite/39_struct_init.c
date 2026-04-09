/* 39_struct_init: 结构体初始化 */

struct S {
    int a;
    int b;
    int c;
};

int main(void) {
    struct S s1 = {10, 20, 30};
    struct S s2 = {.a = 1, .b = 2, .c = 3};
    return s1.a + s1.b + s1.c + s2.a + s2.b + s2.c;
    /* 10+20+30+1+2+3 = 66 */
}
