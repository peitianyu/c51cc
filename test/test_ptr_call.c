// 指针调用约定测试

// 返回指针的函数
int *get_ptr(int *p) {
    return p;
}

// 接受指针参数的函数
int deref(int *p) {
    return *p;
}

// 测试指针调用
int test_ptr(void) {
    int x;
    int *p;
    p = &x;
    *p = 42;
    return deref(p);
}

int main(void) {
    return test_ptr();
}
