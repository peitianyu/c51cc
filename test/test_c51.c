/* test_c51.c - C51 汇编生成测试程序
 * 包含适合 C51 的简单测试用例
 */

// 简单常量返回
int test_ret_const(void) {
    return 42;
}

// 一元运算
int test_not(int a) {
    return ~a;
}

// 二元运算
int test_add(int a, int b) {
    return a + b;
}

int test_sub(int a, int b) {
    return a - b;
}

int test_mul(int a, int b) {
    return a * b;
}

int test_div(int a, int b) {
    return a / b;
}

// 位运算
int test_and(int a, int b) {
    return a & b;
}

int test_or(int a, int b) {
    return a | b;
}

int test_xor(int a, int b) {
    return a ^ b;
}

// 简单条件
int test_max(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

// 简单循环
int test_sum_n(int n) {
    int sum = 0;
    int i = 1;
    while (i <= n) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}

// 函数调用
int test_call(int a, int b) {
    int r = test_add(a, b);
    return r;
}

// 主函数
int main(void) {
    int a = 10;
    int b = 20;
    
    int r1 = test_add(a, b);
    int r2 = test_sub(b, a);
    int r3 = test_max(r1, r2);
    
    return r3;
}
