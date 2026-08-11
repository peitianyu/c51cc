struct S {
    int a;
    float b;
};

int main() {
    struct S s1 = { .a = 42, .b = 3.14 };

    s1.b = 2.718; /* 修改 s1 的成员，确保结构体成员访问正常 */
    /* struct S s2 = s1; // 结构体赋值，s2 应该与 s1 相同 */
    return s1.b;
}