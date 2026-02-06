// // 基本常量折叠 - 整数运算
// int test_const_fold_basic(void) {
//     int a = 2 + 3;           // => 5
//     int b = a * 4;           // => 20
//     int c = b - 5;           // => 15
//     int d = c / 3;           // => 5
//     return d;
// }

// // 复杂常量表达式 - 多级嵌套
// int test_const_fold_complex(void) {
//     int x = (10 + 20) * 2;   // => 60
//     int y = x / 3;           // => 20
//     int z = y & 15;          // => 4
//     int w = z | 8;           // => 12
//     int v = w ^ 7;           // => 11
//     return v;
// }

// // 位运算常量折叠
// int test_const_fold_bitwise(void) {
//     int a = 0xFF & 0x0F;     // => 0x0F
//     int b = 0xF0 | 0x0F;     // => 0xFF
//     int c = 0xFF ^ 0x0F;     // => 0xF0
//     int d = a << 2;          // => 0x3C
//     int e = b >> 4;          // => 0x0F
//     return a + b + c + d + e;
// }

// // 比较运算常量折叠
// int test_const_fold_compare(void) {
//     int a = 10;
//     int b = (5 < 10) + (10 == 10) + (7 > 3);  // => 1 + 1 + 1 = 3
//     return b;
// }

// // 逻辑运算常量折叠
// int test_const_fold_logic(void) {
//     int a = !0;              // => 1
//     int b = !1;              // => 0
//     int c = !!5;             // => 1
//     return a + b + c;
// }

// // ============================================
// // 2. 代数简化测试 (Algebraic Simplification)
// // ============================================

// // x - x = 0
// int test_algebraic_sub_self(int a) {
//     int b = a - a;           // => 0
//     return b;
// }

// // x ^ x = 0
// int test_algebraic_xor_self(int a) {
//     int b = a ^ a;           // => 0
//     return b;
// }

// // x & x = x
// int test_algebraic_and_self(int a) {
//     int b = a & a;           // => a
//     return b;
// }

// // x | x = x
// int test_algebraic_or_self(int a) {
//     int b = a | a;           // => a
//     return b;
// }

// // x * 0 = 0
// int test_algebraic_mul_zero(int a) {
//     int b = a * 0;           // => 0
//     return b;
// }

// // x * 1 = x
// int test_algebraic_mul_one(int a) {
//     int b = a * 1;           // => a
//     return b;
// }

// // x + 0 = x
// int test_algebraic_add_zero(int a) {
//     int b = a + 0;           // => a
//     return b;
// }

// // x - 0 = x
// int test_algebraic_sub_zero(int a) {
//     int b = a - 0;           // => a
//     return b;
// }

// // 0 - x = -x (如果支持)
// int test_algebraic_zero_sub(int a) {
//     int b = 0 - a;           // => -a
//     return b;
// }

// // x / 1 = x
// int test_algebraic_div_one(int a) {
//     int b = a / 1;           // => a
//     return b;
// }

// // ============================================
// // 3. 强度削弱测试 (Strength Reduction)
// // ============================================

// // 乘法转左移
// int test_strength_mul2(int a) { return a * 2; }    // => a << 1
// int test_strength_mul4(int a) { return a * 4; }    // => a << 2
// int test_strength_mul8(int a) { return a * 8; }    // => a << 3
// int test_strength_mul16(int a) { return a * 16; }  // => a << 4
// int test_strength_mul32(int a) { return a * 32; }  // => a << 5

// // 取模转位运算（对2的幂）
// int test_strength_mod2(int a) { return a % 2; }    // => a & 1
// int test_strength_mod4(int a) { return a % 4; }    // => a & 3
// int test_strength_mod8(int a) { return a % 8; }    // => a & 7
// int test_strength_mod16(int a) { return a % 16; }  // => a & 15

// // 除法转右移（对2的幂，unsigned）
// unsigned int test_strength_udiv2(unsigned int a) { return a / 2; }   // => a >> 1
// unsigned int test_strength_udiv4(unsigned int a) { return a / 4; }   // => a >> 2
// unsigned int test_strength_udiv8(unsigned int a) { return a / 8; }   // => a >> 3

// // ============================================
// // 4. 死代码消除测试 (Dead Code Elimination)
// // ============================================

// // 简单死代码
// int test_dce_simple(int a) {
//     int unused1 = a + 10;    // 死代码
//     int unused2 = unused1 * 2; // 死代码
//     int result = a + 1;      // 存活
//     return result;
// }

// // 死代码链
// int test_dce_chain(int x) {
//     int a = x + 1;
//     int b = a * 2;
//     int c = b - 3;           // c 是死的
//     int d = x + 5;           // d 存活
//     return d;
// }

// // 条件死代码
// int test_dce_conditional(int x, int cond) {
//     int a = x + 1;
//     int b = x + 2;
//     if (cond) {
//         return a;
//     } else {
//         return b;
//     }
// }

// // 循环中的死代码
// int test_dce_loop(int n) {
//     int sum = 0;
//     for (int i = 0; i < n; i++) {
//         int dead = i * i;    // 死代码
//         sum = sum + i;
//     }
//     return sum;
// }

// // ============================================
// // 5. PHI 简化测试 (PHI Simplification)
// // ============================================

// // 单值 PHI（所有分支相同）
// int test_phi_same_value(int x, int cond) {
//     int result;
//     if (cond) {
//         result = x;
//     } else {
//         result = x;          // 与 then 分支相同
//     }
//     return result;           // PHI 只有一个有效值 x
// }

// // 常量 PHI
// int test_phi_constant(int cond) {
//     int result;
//     if (cond) {
//         result = 10;
//     } else {
//         result = 10;         // 与 then 分支相同常量
//     }
//     return result;
// }

// // 多分支 PHI
// int test_phi_multi(int x, int a, int b, int c) {
//     int result;
//     if (a) {
//         result = x;
//     } else if (b) {
//         result = x;
//     } else if (c) {
//         result = x;
//     } else {
//         result = x;
//     }
//     return result;
// }

// // ============================================
// // 6. 全局常量优化测试 (Global Constant Optimization)
// // ============================================

// // 只读全局变量
// const int g_const_value = 100;
// const int g_const_arr[4] = {10, 20, 30, 40};

// int test_global_const_read(void) {
//     return g_const_value;    // 应该被优化为常量 100
// }

// int test_global_const_expr(void) {
//     int a = g_const_value + 10;  // => 110
//     return a;
// }

// // 非 const 全局变量（不应该被优化）
// int g_mutable = 50;

// int test_global_mutable(void) {
//     return g_mutable;        // 不应该被优化
// }

// // ============================================
// // 7. 控制流优化测试 (Control Flow Optimization)
// // ============================================

// // 常量条件 - 总是为真
// int test_cf_const_true(int x) {
//     int result;
//     if (1) {                 // 总是为真
//         result = x + 1;
//     } else {
//         result = x - 1;      // 死代码
//     }
//     return result;
// }

// // 常量条件 - 总是为假
// int test_cf_const_false(int x) {
//     int result;
//     if (0) {                 // 总是为假
//         result = x + 1;      // 死代码
//     } else {
//         result = x - 1;
//     }
//     return result;
// }

// // 简化条件
// int test_cf_simplify(int x) {
//     if (x == x) {            // 总是为真
//         return 1;
//     }
//     return 0;
// }

// // ============================================
// // 8. 循环优化测试 (Loop Optimization)
// // ============================================

// // 循环不变量外提
// int test_loop_invariant(int n, int m) {
//     int sum = 0;
//     int inv = m * 10;        // 循环不变量
//     for (int i = 0; i < n; i++) {
//         sum = sum + inv + i;
//     }
//     return sum;
// }

// // 循环中的强度削弱
// int test_loop_strength(int n) {
//     int sum = 0;
//     for (int i = 0; i < n; i++) {
//         sum = sum + i * 8;   // i * 8 => i << 3
//     }
//     return sum;
// }

// // 双重for循环展开
// void test_loop_unroll(int n, int m) {
//     for(int i = 0; i < n; i++) {
//         for(int j = 0; j < m; j++) {
//             __asm__("nop"); // 占位指令，表示循环体
//         }
//     }
// }

// // while 循环
// int test_loop_while(int n) {
//     int sum = 0;
//     int i = 0;
//     while (i < n) {
//         sum = sum + i;
//         i = i + 1;
//     }
//     return sum;
// }

// // do-while 循环
// int test_loop_do_while(int n) {
//     int sum = 0;
//     int i = 0;
//     do {
//         sum = sum + i;
//         i = i + 1;
//     } while (i < n);
//     return sum;
// }

// // ============================================
// // 9. 数组访问优化测试 (Array Access Optimization)
// // ============================================

// // 数组索引常量折叠
// int test_array_const_index(void) {
//     int arr[5] = {10, 20, 30, 40, 50};
//     int a = arr[0];          // => 10
//     int b = arr[1 + 1];      // => arr[2] = 30
//     return a + b;
// }

// // 数组元素访问
// int test_array_access(int *arr, int idx) {
//     int val = arr[idx];
//     return val;
// }

// // 一维数组遍历
// int test_array_1d(int *arr, int n) {
//     int sum = 0;
//     for (int i = 0; i < n; i++) {
//         sum = sum + arr[i];
//     }
//     return sum;
// }

// // ============================================
// // 10. 函数调用优化测试 (Function Call Optimization)
// // ============================================

// // 简单函数
// static int helper_add(int a, int b) {
//     return a + b;
// }

// // 常量参数内联
// int test_call_const_arg(void) {
//     int r = helper_add(2, 3);  // => 5 (如果支持内联)
//     return r;
// }

// // 返回值常量折叠
// int test_call_result_fold(void) {
//     int a = helper_add(1, 2);
//     int b = a + 3;             // => 6
//     return b;
// }

// // 未使用的函数调用结果
// int test_call_unused_result(int a, int b) {
//     helper_add(a, b);          // 未使用结果
//     return a;
// }

// // ============================================
// // 11. 指针优化测试 (Pointer Optimization)
// // ============================================

// // 取地址再解引用
// int test_ptr_deref_addr(int a) {
//     int *p = &a;
//     return *p;               // => a
// }

// // 自增自减
// int test_ptr_inc(int *p) {
//     int a = *p;
//     p = p + 1;
//     int b = *p;
//     return a + b;
// }

// // 指针解引用
// int test_ptr_deref(int *p) {
//     int a = *p;
//     return a;
// }

// // ============================================
// // 12. 位运算优化测试 (Bitwise Optimization)
// // ============================================

// // 位掩码优化
// unsigned int test_bit_mask(unsigned int x) {
//     unsigned int a = x & 0xFFFFFFFF;  // => x (全掩码)
//     unsigned int b = x | 0;           // => x
//     return a + b;
// }

// // 位移组合
// unsigned int test_bit_shift_combo(unsigned int x) {
//     unsigned int a = x << 2;
//     unsigned int b = a >> 2;          // => x (如果低2位为0)
//     return b;
// }

// // 位清零
// unsigned int test_bit_clear(unsigned int x) {
//     return x & ~1;           // 清除最低位
// }

// // 位设置
// unsigned int test_bit_set(unsigned int x) {
//     return x | 1;            // 设置最低位
// }

// // 位切换
// unsigned int test_bit_toggle(unsigned int x) {
//     return x ^ 1;            // 切换最低位
// }

// // ============================================
// // 13. 比较链优化测试 (Comparison Chain)
// // ============================================

// // 双重比较简化
// int test_compare_chain(int x) {
//     int a = (x == 0);        // 布尔值
//     int b = (a != 0);        // => x != 0
//     return b;
// }

// // 布尔值转换
// int test_bool_convert(int x) {
//     if (x) {                 // 非零为真
//         return 1;
//     }
//     return 0;
// }

// // 三元运算符
// int test_ternary(int x, int a, int b) {
//     return x ? a : b;
// }

// // ============================================
// // 14. 综合优化测试 (Comprehensive Tests)
// // ============================================

// // 多个优化组合
// int test_comprehensive1(int n) {
//     int sum = 0;
//     int i = 0;
    
//     while (i < n) {
//         // 常量表达式
//         int offset = 2 + 3 * 4;     // => 14
        
//         // 代数简化: x - x = 0
//         int dummy = offset - offset; // => 0 (死代码)
        
//         // 强度削弱: i * 8 => i << 3
//         int idx = i * 8;
        
//         // 常量表达式
//         int scale = (10 + 6) / 4;   // => 4
        
//         sum = sum + idx * scale + offset;
//         i = i + 1;
//     }
    
//     return sum;
// }

// // 嵌套循环优化
// int test_nested_loops(int n) {
//     int sum = 0;
//     for (int i = 0; i < n; i++) {
//         for (int j = 0; j < n; j++) {
//             int prod = i * j;        // 需要乘法
//             sum = sum + prod;
//         }
//     }
//     return sum;
// }

// // 递归函数（尾递归）
// int test_tail_recursion(int n, int acc) {
//     if (n <= 0) {
//         return acc;
//     }
//     return test_tail_recursion(n - 1, acc + n);
// }

// // 斐波那契（未优化版本）
// int test_fib_naive(int n) {
//     if (n <= 1) {
//         return n;
//     }
//     return test_fib_naive(n - 1) + test_fib_naive(n - 2);
// }

// // 累加函数
// int test_accumulate(int n) {
//     int sum = 0;
//     for (int i = 1; i <= n; i++) {
//         sum = sum + i;
//     }
//     return sum;
// }

// // ============================================
// // 15. 边界情况测试 (Edge Cases)
// // ============================================

// // 空函数
// void test_empty(void) {
// }

// // 仅返回常量
// int test_return_const(void) {
//     return 42;
// }

// // 仅返回参数
// int test_return_param(int x) {
//     return x;
// }

// // 多个返回路径
// int test_multi_return(int x, int cond) {
//     if (cond) {
//         return x + 1;
//     }
//     if (x > 10) {
//         return x * 2;
//     }
//     return x;
// }

// // switch 语句（如果有）
// int test_switch(int x) {
//     int result;
//     switch (x) {
//         case 0: result = 10; break;
//         case 1: result = 20; break;
//         case 2: result = 30; break;
//         default: result = 0; break;
//     }
//     return result;
// }

// // ============================================
// // 16. 主函数 - 调用所有测试
// // ============================================

// int main(void) {
//     int result = 0;
    
//     // 常量折叠测试
//     result += test_const_fold_basic();
//     result += test_const_fold_complex();
//     result += test_const_fold_bitwise();
//     result += test_const_fold_compare();
//     result += test_const_fold_logic();
    
//     // 代数简化测试
//     result += test_algebraic_sub_self(10);
//     result += test_algebraic_xor_self(10);
//     result += test_algebraic_and_self(10);
//     result += test_algebraic_or_self(10);
//     result += test_algebraic_mul_zero(10);
//     result += test_algebraic_mul_one(10);
//     result += test_algebraic_add_zero(10);
//     result += test_algebraic_sub_zero(10);
//     result += test_algebraic_zero_sub(10);
//     result += test_algebraic_div_one(10);
    
//     // 强度削弱测试
//     result += test_strength_mul2(5);
//     result += test_strength_mul4(5);
//     result += test_strength_mul8(5);
//     result += test_strength_mul16(5);
//     result += test_strength_mod8(17);
    
//     // 死代码消除测试
//     result += test_dce_simple(5);
//     result += test_dce_chain(5);
//     result += test_dce_conditional(5, 1);
//     result += test_dce_loop(10);
    
//     // PHI 简化测试
//     result += test_phi_same_value(10, 1);
//     result += test_phi_constant(1);
//     result += test_phi_multi(10, 1, 0, 0);
    
//     // 全局常量测试
//     result += test_global_const_read();
//     result += test_global_const_expr();
//     result += test_global_mutable();
    
//     // 控制流优化测试
//     result += test_cf_const_true(5);
//     result += test_cf_const_false(5);
//     result += test_cf_simplify(5);
    
//     // 循环优化测试
//     result += test_loop_invariant(10, 3);
//     result += test_loop_strength(10);
//     result += test_loop_while(10);
//     result += test_loop_do_while(10);
    
//     // 数组测试
//     result += test_array_const_index();
    
//     // 函数调用测试
//     result += test_call_const_arg();
//     result += test_call_result_fold();
//     result += test_call_unused_result(3, 4);
    
//     // 指针测试
//     int ptr_test_val = 42;
//     result += test_ptr_deref_addr(ptr_test_val);
    
//     // 位运算测试
//     result += test_bit_mask(0x12345678);
//     result += test_bit_shift_combo(0xFFFFFFFC);
//     result += test_bit_clear(0xFF);
//     result += test_bit_set(0xFE);
//     result += test_bit_toggle(0xFF);
    
//     // 比较链测试
//     result += test_compare_chain(0);
//     result += test_bool_convert(5);
//     result += test_ternary(1, 10, 20);
    
//     // 综合测试
//     result += test_comprehensive1(10);
//     result += test_accumulate(10);
    
//     // 边界情况
//     result += test_return_const();
//     result += test_return_param(10);
//     result += test_multi_return(5, 0);
//     result += test_switch(1);
    
//     return result;
// }
