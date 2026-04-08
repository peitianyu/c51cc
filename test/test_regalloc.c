// =====================================================
// 寄存器分配测试套件
// 用于验证线性寄存器分配算法的效果
// =====================================================

// 测试SFR定义
#ifdef __C51__
sfr P1 = 0x90;
sfr P0 = 0x80;
#else
register char P1 = 0x90;
register char P0 = 0x80;
#endif

// 测试全局变量
unsigned char g_temp1 = 0;
unsigned char g_temp2 = 0;
int g_result = 0;

// ----- 测试1：简单算术运算，多个临时变量 -----
int test_simple_arith(int a, int b, int c) {
    int x = a + b;
    int y = b + c;
    int z = x + y;
    int w = z * 2;
    return w;
}

// ----- 测试2：多个char变量 -----
char test_char_ops(char a, char b, char c) {
    char x = a + b;
    char y = x + c;
    char z = y - a;
    char w = z ^ b;
    return w;
}

// ----- 测试3：混合类型操作 -----
int test_mixed_types(char a, int b, char c) {
    int x = (int)a + b;
    char y = (char)(x + (int)c);
    int z = x + (int)y;
    char w = (char)z;
    return (int)w + x;
}

// ----- 测试4：SFR多次读写 -----
int test_sfr_multiple_ops(int v) {
    int sum = 0;
    
    P1 = (char)v;
    sum += P1;
    
    P1 = (char)(v + 1);
    sum += P1;
    
    P1 = (char)(v + 2);
    sum += P1;
    
    P1 = (char)(v + 3);
    sum += P1;
    
    return sum;
}

// ----- 测试5：局部变量寿命不同 -----
int test_live_ranges(int a, int b, int c) {
    int x = a + b;        // x用于一个操作后就不再用
    int result = x * 2;   // 立即使用x
    int y;
    int z;
    
    y = b + c;        // y是独立的生命周期
    result += y;
    
    z = a - c;        // z再次独立
    result += z;
    
    return result;
}

// ----- 测试6：逻辑运算链 -----
int test_logic_chain(int a, int b) {
    int x = a & 0xFF;
    int y = x | 0x0F;
    int z = y ^ 0xAA;
    int w = z | 0x55;
    int v = w & 0x3F;
    return v;
}

// ----- 测试7：位运算密集 -----
char test_bitwise_ops(char a) {
    char x = a << 1;
    char y = x >> 1;
    char z = ~a;
    char w = a & 0x0F;
    char v = w | 0xF0;
    return v;
}

// ----- 测试8：数组访问 -----
char test_array_access(void) {
    char arr[5] = {0x05, 0x04, 0x03, 0x02, 0x01};
    char x = arr[0];
    char y = arr[1];
    char z = arr[2];
    char w = arr[3];
    return x + y + z + w;
}

char* test_array_access2(char *arr) {
    arr[0] = 1;
    return arr;
}

// ----- 测试9：条件表达式 -----
int test_ternary_expr(int a, int b, int c) {
    int x = (a > b) ? a : b;
    int y = (b > c) ? b : c;
    int z = (x > y) ? x : y;
    return z;
}

// ----- 测试10：循环中的寄存器使用 -----
int test_loop_regs(int n) {
    int sum = 0;
    int i;
    int x;
    int y;
    
    for (i = 0; i < n; i++) {
        x = i * 2;
        y = x + 1;
        sum += y;
    }
    
    return sum;
}

// ----- 测试11：嵌套表达式 -----
int test_nested_expr(int a, int b, int c, int d) {
    int result = (a + b) * (c + d) + (a - b) * (c - d);
    return result;
}

// ----- 测试12：SFR与局部变量混合 -----
int test_sfr_with_locals(int v1, int v2) {
    int a = v1 + 10;
    int b = v2 + 20;
    int c;
    int d;
    
    P1 = (char)a;
    c = (int)P1 + b;
    
    P1 = (char)c;
    d = (int)P1 + a;
    
    return c + d;
}

// ----- 测试13：函数调用 -----
int helper_func(int x, int y) {
    return x * y + x + y;
}

int test_func_calls(int a, int b, int c) {
    int x = helper_func(a, b);
    int y = helper_func(b, c);
    int z = helper_func(x, y);
    return z;
}

// ----- 测试14：返回复杂表达式 -----
int test_complex_return(int a, int b, int c) {
    return (a + b) * c - (a - b) / (c + 1);
}

// ----- 测试15：多个参数的处理 -----
int test_many_params(char p1, char p2, char p3, char p4, char p5, char p6) {
    int x = (int)p1 + (int)p2;
    int y = (int)p3 + (int)p4;
    int z = (int)p5 + (int)p6;
    return x + y + z;
}

// ===== 主函数：汇总测试 =====
int main(void) {
    int result = 0;
    
    result += test_simple_arith(1, 2, 3);
    result += test_char_ops(10, 20, 30);
    result += test_mixed_types(5, 100, 10);
    result += test_sfr_multiple_ops(0x55);
    result += test_live_ranges(10, 20, 30);
    result += test_logic_chain(0xAA, 0x55);
    result += test_bitwise_ops(0x12);
    result += test_array_access();
    result += test_ternary_expr(5, 10, 8);
    result += test_loop_regs(5);
    result += test_nested_expr(2, 3, 4, 5);
    result += test_sfr_with_locals(10, 20);
    result += test_func_calls(2, 3, 4);
    result += test_complex_return(10, 5, 3);
    result += test_many_params(1, 2, 3, 4, 5, 6);
    
    P1 = (char)result;
    
    return result;
}
