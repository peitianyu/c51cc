// 测试全局变量初始化, 并折叠常量
int g_a = 1;
// int g_a0 = 1+2/1*(1+3);
// int g_a1 = 1 | 2;
// int g_a2 = 1 & 2;
// int g_a3 = !0;
// int g_a4 = 1 << 3;
// int g_a5 = 0 && 55;
// int g_a6 = 0 != 55;
// int g_arr[3] = {1, 2, 3};
// int g_arr1[] = {1, 2, 3};
// // char g_arr2[] = "123";
// // char* g_arr2 = "abc";

// struct A{
//     int a;
//     int b;
// };

// // FIXME: 存在问题, 需要解一下 
// union B {
//     float c;
//     int b;
// };

// void test_var_init()
// {
//     struct A a = {1, 2};
//     struct A a1 = {.a = 1, .b = 2};
//     union B b;
// }



int test_basic_arith() {
    // FIXME: 这部分应该在前端就做一下常量折叠
    int a = 1+2/3*(1+4);
    return a + 4;
}

int main() {
    

    return test_basic_arith();
}