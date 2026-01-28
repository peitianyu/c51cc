/**
 * 语法分析测试文件
 * 用于测试MazuCC编译器支持的所有语法特性
 */

/*=============================*
 * 一、基础类型与变量声明测试
 *=============================*/

// 全局变量声明
int g_int;
char g_char;
float g_float;
double g_double;
int g_bool;
long g_long;

// 全局变量初始化
int g_init_int = 42;
char g_init_char = 'A';
float g_init_float = 3.14;
double g_init_double = 2.71828;

// 数组声明与初始化
int g_arr[5];
int g_arr_init[3] = {1, 2, 3};
int g_arr_infer[] = {10, 20, 30};
char g_str[] = "Hello";

// 多维数组
int g_2d_arr[2][3];
int g_2d_init[2][3] = {{1, 2, 3}, {4, 5, 6}};
int g_2d_infer[][2] = {{1, 2}, {3, 4}, {5, 6}};

// 指针声明
int *g_ptr;
char *g_str_ptr;
int **g_ptr_ptr;
int *g_arr_ptr[5];

/*=============================*
 * 二、结构体与联合体测试
 *=============================*/

// 结构体定义与变量声明
struct Point {
    int x;
    int y;
};

struct Point g_point;
struct Point g_point_init = {10, 20};
struct Point g_point_named = {.x = 5, .y = 15};

// 嵌套结构体
struct Rect {
    struct Point tl;
    struct Point br;
};

struct Rect g_rect = {{0, 0}, {100, 100}};

// 联合体
union Data {
    int i;
    float f;
    char c;
};

union Data g_data;

// 位域结构体
struct BitField {
    int a: 4;
    int b: 8;
    int c: 4;
};

struct BitField g_bitfield;

/*=============================*
 * 三、枚举类型测试
 *=============================*/

enum Color {
    RED,
    GREEN,
    BLUE
};

enum Status {
    OK = 0,
    ERROR = 1,
    PENDING = 2
};

enum Color g_color = RED;
enum Status g_status = OK;

/*=============================*
 * 四、typedef测试
 *=============================*/

typedef int Integer;
typedef char* String;
typedef struct Point Point_t;

Integer g_typedef_int = 100;
String g_typedef_str;
Point_t g_typedef_point;

/*=============================*
 * 五、函数声明与定义测试
 *=============================*/

// 函数声明
int func_decl(int a, int b);
void func_void();

// 基础函数定义
int add(int a, int b) {
    return a + b;
}

// 多参数函数
int sum3(int a, int b, int c) {
    return a + b + c;
}

// 无返回值函数
void print_int(int n) {
    // 空函数体
}

// 递归函数
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// 函数指针参数
int apply(int (*fn)(int), int x) {
    return fn(x);
}

// 数组参数
int sum_array(int arr[], int n) {
    int sum = 0;
    for (int i = 0; i < n; i = i + 1) {
        sum = sum + arr[i];
    }
    return sum;
}

/*=============================*
 * 六、表达式与运算符测试
 *=============================*/

int test_arithmetic() {
    // int a = 10, b = 3;
    int a = 10;
    int b = 3;
    int r;
    
    // 算术运算符
    r = a + b;    // 加法
    r = a - b;    // 减法
    r = a * b;    // 乘法
    r = a / b;    // 除法
    r = a % b;    // 取模
    
    return r;
}

int test_bitwise() {
    int a = 0x0F;
    int b = 0xF0;
    int r;
    
    // 位运算符
    r = a & b;    // 与
    r = a | b;    // 或
    r = a ^ b;    // 异或
    r = ~a;       // 取反
    r = a << 2;   // 左移
    r = a >> 2;   // 右移
    
    return r;
}

int test_comparison() {
    int a = 5; 
    int b = 10;
    int r;
    
    // 比较运算符
    r = a == b;   // 等于
    r = a != b;   // 不等于
    r = a < b;    // 小于
    r = a > b;    // 大于
    r = a <= b;   // 小于等于
    r = a >= b;   // 大于等于
    
    return r;
}

int test_logical() {
    int a = 1, b = 0;
    int r;
    
    // 逻辑运算符
    r = a && b;   // 逻辑与
    r = a || b;   // 逻辑或
    r = !a;       // 逻辑非
    
    return r;
}

int test_unary() {
    int a = 5;
    int *p;
    int r;
    
    // 一元运算符
    r = +a;       // 正号
    r = -a;       // 负号
    r = ++a;      // 前置自增
    r = a++;      // 后置自增
    r = --a;      // 前置自减
    r = a--;      // 后置自减
    
    p = &a;       // 取地址
    r = *p;       // 解引用
    
    return r;
}

int test_ternary() {
    int a = 5, b = 10;
    int r;
    
    // 三元运算符
    r = (a > b) ? a : b;
    r = (a < b) ? 100 : 200;
    
    return r;
}

int test_assignment() {
    int a = 10;
    int b;
    
    // 赋值运算符
    b = a;
    b = a + 5;
    b = a * 2 + 3;
    
    return b;
}

int test_cast() {
    int a = 10;
    float f = 3.14;
    int r;
    
    // 类型转换
    r = (int)f;
    f = (float)a;
    r = (int)3.7;
    
    return r;
}

/*=============================*
 * 七、控制流语句测试
 *=============================*/

int test_if() {
    int a = 10;
    int b = 20;
    int r = 0;
    
    // 简单if
    if (a > 5) {
        r = 1;
    }
    
    // if-else
    if (a > b) {
        r = a;
    } else {
        r = b;
    }
    
    // if-else if-else (嵌套实现)
    if (a > 20) {
        r = 1;
    } else {
        if (a > 15) {
            r = 2;
        } else {
            if (a > 10) {
                r = 3;
            } else {
                r = 4;
            }
        }
    }
    
    // 嵌套if
    if (a > 5) {
        if (b > 15) {
            r = a + b;
        }
    }
    
    return r;
}

int test_for() {
    int sum = 0;
    int i;
    
    // 基础for循环
    for (i = 0; i < 10; i = i + 1) {
        sum = sum + i;
    }
    
    // for循环内声明变量
    for (int j = 0; j < 5; j = j + 1) {
        sum = sum + j;
    }
    
    // 空初始化
    int k = 0;
    for (; k < 5; k = k + 1) {
        sum = sum + 1;
    }
    
    // 空条件（无限循环，需内部break，这里省略）
    // for (int m = 0; ; m = m + 1) { break; }
    
    return sum;
}

int test_while() {
    int sum = 0;
    int i = 0;
    
    // while循环
    while (i < 10) {
        sum = sum + i;
        i = i + 1;
    }
    
    return sum;
}

int test_dowhile() {
    int sum = 0;
    int i = 0;
    
    // do-while循环
    do {
        sum = sum + i;
        i = i + 1;
    } while (i < 10);
    
    return sum;
}

int test_switch() {
    int a = 2;
    int r = 0;
    
    // switch语句
    switch (a) {
        case 0:
            r = 100;
            break;
        case 1:
            r = 200;
            break;
        case 2:
            r = 300;
            break;
        default:
            r = 999;
            break;
    }
    
    return r;
}

int test_goto() {
    int r = 0;
    
    goto skip;
    r = 100;  // 被跳过
skip:
    r = 200;
    
    return r;
}

int test_break_continue() {
    int sum = 0;
    
    // break测试
    for (int i = 0; i < 100; i = i + 1) {
        if (i == 10) {
            break;
        }
        sum = sum + i;
    }
    
    // continue测试
    sum = 0;
    for (int i = 0; i < 10; i = i + 1) {
        if (i == 5) {
            continue;
        }
        sum = sum + i;
    }
    
    return sum;
}

/*=============================*
 * 八、复合语句测试
 *=============================*/

int test_compound_stmt() {
    int a = 10;
    
    {
        int b = 20;
        a = a + b;
    }
    
    {
        int b = 30;
        a = a + b;
    }
    
    return a;
}

/*=============================*
 * 九、指针操作测试
 *=============================*/

int test_pointer() {
    int a = 10;
    int *p = &a;
    int r;
    
    r = *p;           // 解引用
    *p = 20;          // 通过指针赋值
    r = *p;
    
    return r;
}

int test_pointer_arithmetic() {
    int arr[5] = {10, 20, 30, 40, 50};
    int *p = arr;
    int r;
    
    r = *p;           // arr[0]
    p = p + 1;
    r = *p;           // arr[1]
    r = *(p + 2);     // arr[3]
    
    return r;
}

int test_array_access() {
    int arr[5] = {10, 20, 30, 40, 50};
    int r;
    
    r = arr[0];
    r = arr[2];
    r = arr[1 + 2];
    
    // 指针数组访问
    int *p = arr;
    r = p[3];
    r = 3[p];         // 等价于 p[3]
    
    return r;
}

/*=============================*
 * 十、结构体操作测试
 *=============================*/

int test_struct() {
    struct Point p;
    int r;
    
    // 成员访问
    p.x = 10;
    p.y = 20;
    r = p.x + p.y;
    
    // 结构体指针
    struct Point *ptr = &p;
    ptr->x = 30;      // 箭头访问
    ptr->y = 40;
    r = ptr->x + ptr->y;
    
    // 嵌套结构体
    struct Rect rect;
    rect.tl.x = 0;
    rect.tl.y = 0;
    rect.br.x = 100;
    rect.br.y = 100;
    r = rect.br.x - rect.tl.x;
    
    return r;
}

/*=============================*
 * 十一、联合体操作测试
 *=============================*/

int test_union() {
    union Data d;
    int r;
    
    d.i = 100;
    r = d.i;
    
    d.f = 3.14;
    // 注意：此时访问d.i是未定义行为，仅测试语法
    
    return r;
}

/*=============================*
 * 十二、复杂表达式测试
 *=============================*/

int test_complex_expr() {
    int a = 5, b = 3, c = 2;
    int r;
    
    // 复杂算术表达式
    r = a + b * c;           // 优先级测试
    r = (a + b) * c;         // 括号测试
    r = a * b + c * 2;       // 混合运算
    
    // 复杂逻辑表达式
    r = (a > b) && (b > c);
    r = (a == 5) || (b == 10);
    r = !(a < b);
    
    // 混合位运算
    r = (a & b) | (c << 1);
    r = a ^ b ^ c;
    
    // 多层嵌套
    r = ((a + b) * (c - 1)) / 2;
    
    return r;
}

/*=============================*
 * 十三、综合测试函数
 *=============================*/

int test_all_features() {
    int result = 0;
    
    // 测试所有功能
    result = result + test_arithmetic();
    result = result + test_bitwise();
    result = result + test_comparison();
    result = result + test_logical();
    result = result + test_unary();
    result = result + test_ternary();
    result = result + test_assignment();
    result = result + test_cast();
    result = result + test_if();
    result = result + test_for();
    result = result + test_while();
    result = result + test_dowhile();
    result = result + test_switch();
    result = result + test_goto();
    result = result + test_break_continue();
    result = result + test_compound_stmt();
    result = result + test_pointer();
    result = result + test_pointer_arithmetic();
    result = result + test_array_access();
    result = result + test_struct();
    result = result + test_union();
    result = result + test_complex_expr();
    
    return result;
}

/*=============================*
 * 十四、main函数
 *=============================*/

int main() {
    int result = test_all_features();
    return result;
}
