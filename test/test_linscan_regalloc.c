// 线性扫描寄存器分配测试
// 测试多个值竞争有限的R0/R1/R2寄存器的情况

// 测试1: 多个值在短生命周期内竞争寄存器
int test_multi_values(int a, int b, int c) {
    int v1 = a + b;        // v1 在v6被使用后就不再用了
    int v2 = c - a;        // v2 在v5被使用后就不再用了
    int v3 = b * 2;        // v3（暂不支持乘法）
    int v4 = a & c;        // v4 在v6被使用后就不再用了
    int v5 = v2 + v1;      // v5 使用了v2和v1
    int v6 = v4 + v5;      // v6 是最终结果
    return v6;
}

// 测试2: 值的生命周期重叠
int test_overlapping_lifetimes(int x, int y) {
    int a = x + 1;
    int b = y + 2;
    int c = a + b;
    int d = a - b;
    int e = c + d;
    int f = c * e;  // 注意：乘法暂不支持
    return e;
}

// 测试3: 长生命周期的值优先保留
int test_long_lifetime(int p, int q, int r) {
    int long_val = p + q;  // 长生命周期：start=0, end=4
    int short1 = r - p;    // 短生命周期：start=1, end=2
    int short2 = q & r;    // 短生命周期：start=2, end=3
    
    short1 = short1 + 1;
    short2 = short2 | 2;
    
    return long_val + short1 + short2;
}

// 测试4: 连续的操作序列
int test_sequential_ops(int a, int b) {
    int r = a + b;
    r = r - 1;
    r = r + 2;
    r = r & 15;
    r = r | 48;
    r = r ^ 1;
    return r;
}

// 测试5: 参数直接使用（不应重新分配）
int test_param_reuse(int x, int y, int z) {
    int sum = x + y + z;
    return sum;
}
