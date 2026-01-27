// SSA 优化测试文件
// 本文件包含用于测试各种 SSA 优化的 C 代码示例

// ======== 常量折叠测试 ========
// 预期: v1 = const 10 (2+3*4-2 = 2+12-2 = 12, 但这里是简单的常量表达式)
int test_const_fold1(void) {
    int a = 2 + 3;           // => 5
    int b = a * 4;           // => 20
    int c = b - 5;           // => 15
    return c;
}

// 复杂常量表达式
int test_const_fold2(void) {
    int x = (10 + 20) * 2;   // => 60
    int y = x / 3;           // => 20
    int z = y & 15;          // => 4
    return z;
}

// ======== 代数简化测试 ========
// x - x = 0
int test_algebraic1(int a) {
    int b = a - a;           // => 0
    return b;
}

// x ^ x = 0
int test_algebraic2(int a) {
    int b = a ^ a;           // => 0
    return b;
}

// x & x = x
int test_algebraic3(int a) {
    int b = a & a;           // => a
    return b;
}

// x | x = x
int test_algebraic4(int a) {
    int b = a | a;           // => a
    return b;
}

// ======== 死代码消除测试 ========
// 未使用的计算应该被删除
int test_dce1(int a) {
    int unused1 = a + 10;    // 死代码
    int unused2 = unused1 * 2; // 死代码
    int result = a + 1;      // 存活
    return result;
}

// 更复杂的死代码链
int test_dce2(int x) {
    int a = x + 1;
    int b = a * 2;
    int c = b - 3;           // c 是死的
    int d = x + 5;           // d 存活
    return d;
}

// ======== 强度削弱测试 ========
// x * 8 => x << 3
int test_strength1(int a) {
    int b = a * 8;
    return b;
}

// x * 16 => x << 4
int test_strength2(int a) {
    int b = a * 16;
    return b;
}

// x % 8 => x & 7
int test_strength3(int a) {
    int b = a % 8;
    return b;
}

// ======== PHI 简化测试 ========
// 单参数 PHI 应该被简化
int test_phi_simplify(int x, int cond) {
    int result;
    if (cond) {
        result = x;
    } else {
        result = x;          // 与 then 分支相同
    }
    return result;           // PHI 只有一个有效值 x
}

// ======== 控制流优化测试 ========
// 常量条件应该简化跳转
int test_cf_opt1(int x) {
    int result;
    if (1) {                 // 总是为真
        result = x + 1;
    } else {
        result = x - 1;      // 死代码
    }
    return result;
}

// ======== 综合测试 ========
int test_comprehensive(int n) {
    int sum = 0;
    int i = 0;
    
    while (i < n) {
        // 常量表达式
        int offset = 2 + 3 * 4;  // => 14
        
        // 代数简化: x - x = 0 (如果 offset 不变)
        int dummy = offset - offset; // => 0 (死代码)
        
        // 强度削弱: i * 8 => i << 3
        int idx = i * 8;
        
        sum = sum + idx + offset;
        i = i + 1;
    }
    
    return sum;
}

// ======== 简单主函数 ========
int main(void) {
    int a = 10;
    int b = 20;
    
    int r1 = test_const_fold1();
    int r2 = test_algebraic1(a);
    int r3 = test_strength1(b);
    int r4 = test_dce1(a);
    
    return r1 + r2 + r3 + r4;
}
