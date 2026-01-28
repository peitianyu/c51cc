/**
 * 函数指针专项测试文件
 * 测试MazuCC编译器的函数指针支持
 * 
 * 当前支持的功能:
 * 1. 函数指针声明: int (*fp)(int, int);
 * 2. 函数指针初始化: int (*fp)(int, int) = func_name;
 * 3. 函数指针赋值: fp = func_name;
 * 4. 函数指针调用: fp(args);
 * 5. 函数指针作为参数: int foo(int (*fp)(int), int x);
 * 6. typedef函数指针: typedef int (*op_t)(int, int);
 * 
 * 暂不支持的功能:
 * 1. 结构体中的函数指针字段赋值
 * 2. 返回函数指针的函数
 * 3. 函数指针数组
 * 4. (*fp)(args) 解引用调用语法
 */

//=============================
// 基础函数定义
//=============================
int add(int a, int b) {
    return a + b;
}

int mul(int a, int b) {
    return a * b;
}

//=============================
// 1. 基础函数指针测试
//=============================

// 函数指针声明
void test_func_ptr_decl() {
    int (*fp1)(int, int);
    int (*fp2)(int);
}

// 函数指针初始化与赋值
int test_func_ptr_init() {
    int (*fp)(int, int) = add;
    return fp(2, 3);
}

// 函数指针调用
int test_func_ptr_call() {
    int (*fp)(int, int);
    fp = add;
    int r = fp(3, 4);
    return r;
}

//=============================
// 2. 函数指针作为参数
//=============================
int apply_op(int (*op)(int, int), int a, int b) {
    return op(a, b);
}

int test_func_ptr_as_param() {
    return apply_op(add, 5, 6);
}

//=============================
// 3. 使用typedef的函数指针
//=============================
typedef int (*binary_op_t)(int, int);

int test_typedef_func_ptr() {
    binary_op_t op = mul;
    return op(2, 5);
}

//=============================
// 4. 函数指针数组 (暂不支持)
//=============================
// void test_func_ptr_array() {
//     int (*fp_arr[3])(int, int);
//     fp_arr[0] = add;
// }

//=============================
// 5. 结构体中的函数指针 (暂不支持)
//=============================
// struct Ops {
//     int (*add)(int, int);
//     int (*mul)(int, int);
// };
// 
// int test_struct_func_ptr() {
//     struct Ops ops;
//     ops.add = add;  // 这里会报错: Invalid var init
//     ops.mul = mul;
//     return ops.add(3, 4) + ops.mul(2, 5);
// }

//=============================
// 综合测试
//=============================
int test_all_func_ptr() {
    int result = 0;
    
    test_func_ptr_decl();
    result = result + test_func_ptr_init();
    result = result + test_func_ptr_call();
    result = result + test_func_ptr_as_param();
    result = result + test_typedef_func_ptr();
    // result = result + test_struct_func_ptr();  // 暂不支持
    
    return result;
}

//=============================
// main函数
//=============================
int main() {
    int result = test_all_func_ptr();
    return result;
}
