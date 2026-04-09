/* 40_struct_nested: 嵌套结构体 */

struct Inner {
    int a;
    int b;
};

struct Outer {
    struct Inner p1;
    struct Inner p2;
};

int main(void) {
    struct Outer o;
    o.p1.a = 1;
    o.p1.b = 2;
    o.p2.a = 3;
    o.p2.b = 4;
    return o.p1.a + o.p1.b + o.p2.a + o.p2.b;  /* 10 */
}
