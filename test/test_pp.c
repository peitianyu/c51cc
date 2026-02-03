#include "test_pp_include.h"

/*=============================*
 * 一、基本宏定义测试 (对象式宏)
 *=============================*/

#define PI 314
#define MAX_VALUE 1000
#define MIN_VALUE 0

// 使用基本宏
int test_basic_define() {
    int a = PI;
    int b = MAX_VALUE;
    int c = MIN_VALUE;
    return a + b + c;
}

/*=============================*
 * 二、宏用于常量表达式
 *=============================*/

#define OFFSET 100
#define MULTIPLIER 2
#define BASE 10

int test_macro_expr() {
    int r;
    r = OFFSET;
    r = r + MULTIPLIER;
    r = r * BASE;
    return r;
}

/*=============================*
 * 三、条件编译测试 (#ifdef, #ifndef)
 *=============================*/

#define DEBUG_MODE

#ifdef DEBUG_MODE
int debug_enabled = 1;
#else
int debug_enabled = 0;
#endif

#ifndef RELEASE_MODE
int is_release = 0;
#else
int is_release = 1;
#endif

// 测试条件编译
int test_conditional_compile() {
    int r = 0;
    r = r + debug_enabled;
    r = r + is_release;
    return r;
}

/*=============================*
 * 四、#undef 测试
 *=============================*/

#define TEMP_MACRO 100

int test_undef() {
    int r = TEMP_MACRO;
#ifdef TEMP_MACRO
    r = r + 1;
#endif
#undef TEMP_MACRO
#ifndef TEMP_MACRO
    r = r + 10;
#endif
    return r;
}

/*=============================*
 * 五、复杂条件编译测试
 *=============================*/

#define LEVEL 2
#define FEATURE_A

#ifdef FEATURE_A
int feature_a_enabled = 1;
#else
int feature_a_enabled = 0;
#endif

#ifdef LEVEL
int level_defined = 1;
#else
int level_defined = 0;
#endif

// 测试复杂条件编译
int test_complex_conditional() {
    return feature_a_enabled + level_defined;
}

/*=============================*
 * 六、宏在代码中的各种使用场景
 *=============================*/

#define ARRAY_SIZE 10
#define LOOP_COUNT 5
#define INIT_VALUE 0

int test_macro_in_code() {
    int arr[ARRAY_SIZE];
    int sum = INIT_VALUE;
    int i;
    
    for (i = 0; i < LOOP_COUNT; i = i + 1) {
        arr[i] = i + OFFSET;
        sum = sum + arr[i];
    }
    
    return sum;
}

/*=============================*
 * 七、宏用于控制代码结构
 *=============================*/

#define USE_FAST_PATH

int test_code_structure() {
    int r = 0;
    
#ifdef USE_FAST_PATH
    r = 100;
#else
    r = 200;
#endif
    
    return r;
}

/*=============================*
 * 八、条件编译嵌套测试
 *=============================*/

#define CONFIG_A
#define CONFIG_B

int test_nested_conditional() {
    int r = 0;
    
#ifdef CONFIG_A
    r = r + 1;
#ifdef CONFIG_B
    r = r + 10;
#else
    r = r + 100;
#endif
#else
    r = r + 1000;
#endif
    
    return r;
}

/*=============================*
 * 九、#else 分支测试
 *=============================*/

// UNDEFINED_MACRO 未定义

int test_else_branch() {
    int r;
    
#ifdef UNDEFINED_MACRO
    r = 100;
#else
    r = 200;
#endif
    
#ifndef UNDEFINED_MACRO
    r = r + 1;
#else
    r = r + 2;
#endif
    
    return r;
}

/*=============================*
 * 十、宏常量用于数组大小
 *=============================*/

#define BUFFER_SIZE 256
#define SMALL_BUF 16

int test_macro_array_size() {
    char buf1[BUFFER_SIZE];
    int buf2[SMALL_BUF];
    int i;
    
    for (i = 0; i < SMALL_BUF; i = i + 1) {
        buf2[i] = i;
    }
    
    int sum = 0;
    for (i = 0; i < SMALL_BUF; i = i + 1) {
        sum = sum + buf2[i];
    }
    
    return sum;
}

/*=============================*
 * 十一、布尔宏测试
 *=============================*/

#define TRUE_VAL 1
#define FALSE_VAL 0

int test_bool_macro() {
    int flag = TRUE_VAL;
    int result = 0;
    
    if (flag == TRUE_VAL) {
        result = 1;
    } else {
        result = 0;
    }
    
    return result;
}

/*=============================*
 * 十二、宏用于开关功能
 *=============================*/

#define ENABLE_LOGGING
#define LOG_LEVEL 2

#ifdef ENABLE_LOGGING
int log_enabled = 1;
int log_level_val = LOG_LEVEL;
#else
int log_enabled = 0;
int log_level_val = 0;
#endif

int test_feature_switches() {
    return log_enabled + log_level_val;
}

/*=============================*
 * 十三、多宏组合测试
 *=============================*/

#define VAL1 10
#define VAL2 20
#define VAL3 30

int test_multi_macro() {
    int r;
    r = VAL1 + VAL2 + VAL3;
    return r;
}

/*=============================*
 * 十四、宏在初始化中使用
 *=============================*/

#define INIT_X 5
#define INIT_Y 10

int test_macro_init() {
    int x = INIT_X;
    int y = INIT_Y;
    return x + y;
}

/*=============================*
 * 十五、#include 测试
 *=============================*/

int test_include() {
    int r = 0;
    
    // 测试从 include 文件引入的宏
    r = r + INCLUDE_MACRO;      // 42
    r = r + INCLUDE_OFFSET;     // 1000
    
    // 测试从 include 文件引入的条件编译宏
#ifdef INCLUDE_FEATURE_ENABLED
    r = r + 100;
#endif

    // 测试从 include 文件引入的数组大小宏
    int arr[INCLUDE_ARRAY_SIZE];
    int i;
    for (i = 0; i < INCLUDE_ARRAY_SIZE; i = i + 1) {
        arr[i] = i;
        r = r + arr[i];
    }
    
    // 测试从 include 文件引入的结构体
    struct IncludeStruct s;
    s.x = 10;
    s.y = 20;
    r = r + s.x + s.y;
    
    return r;
}

/*=============================*
 * 十七、函数式宏测试
 *=============================*/

#define ADD(a, b) ((a) + (b))
#define MUL(a, b) ((a) * (b))
#define INC(x) ((x) + 1)
#define WRAP(x) (x)

int test_func_like_macro() {
    int r = 0;
    r = r + ADD(1, 2);
    r = r + MUL(3, 4);
    r = r + INC(10);
    r = r + WRAP(ADD(5, 6));
    return r;
}

/*=============================*
 * 十八、递归/嵌套宏展开测试
 *=============================*/

#define NEST_A 7
#define NEST_B NEST_A
#define NEST_C NEST_B

int test_nested_macro_expand() {
    int r = 0;
    r = r + NEST_C; /* 期望最终展开为 7 */
    return r;
}

/*=============================*
 * 十九、do { } while(0) 语句宏测试
 *=============================*/

#define ADD_TO_RESULT(res, v) do { (res) = (res) + (v); } while (0)

int test_do_while_0_macro() {
    int result = 0;

    ADD_TO_RESULT(result, 1);
    ADD_TO_RESULT(result, 2);

    /* 典型 if/else 场景：要求宏能作为单语句使用 */
    if (1)
        ADD_TO_RESULT(result, 3);
    else
        ADD_TO_RESULT(result, 1000);

    return result;
}

/*=============================*
 * 二十、多行宏（\\ 续行）测试
 *=============================*/

#define MULTI_ADD(a, b) \
    ((a) + \
     (b))

#define MULTI_STMT(res) \
    do { \
        (res) = (res) + 10; \
        (res) = (res) + 20; \
    } while (0)

int test_multiline_macro() {
    int r = 0;
    r = r + MULTI_ADD(1, 2);
    MULTI_STMT(r);

    /* 多行注释跨行：预处理器不应在注释内做宏替换 */
    /* MULTI_ADD(100, 200)
       MULTI_STMT(r)
     */

    return r;
}

/*=============================*
 * 二十一、#if / #elif 常量表达式测试
 *=============================*/

#define IF_MACRO_VAL 3

#if 0
int if_expr_a = 1000;
#elif 1
int if_expr_a = 10;
#else
int if_expr_a = 2000;
#endif

#if (1 + 2 * 3) == 7
int if_expr_b = 1;
#else
int if_expr_b = 0;
#endif

#if IF_MACRO_VAL > 2
int if_expr_c = 5;
#else
int if_expr_c = 0;
#endif

#if defined(DEBUG_MODE)
int if_expr_d = 7;
#else
int if_expr_d = 0;
#endif

#if defined(UNDEFINED_MACRO)
int if_expr_e = 100;
#elif defined(UNDEFINED_MACRO2)
int if_expr_e = 200;
#else
int if_expr_e = 3;
#endif

int test_if_elif_expr() {
    return if_expr_a + if_expr_b + if_expr_c + if_expr_d + if_expr_e;
}

/*=============================*
 * 十六、综合测试函数
 *=============================*/

int test_all_pp_features() {
    int result = 0;
    
    result = result + test_basic_define();
    result = result + test_macro_expr();
    result = result + test_conditional_compile();
    result = result + test_undef();
    result = result + test_complex_conditional();
    result = result + test_macro_in_code();
    result = result + test_code_structure();
    result = result + test_nested_conditional();
    result = result + test_else_branch();
    result = result + test_macro_array_size();
    result = result + test_bool_macro();
    result = result + test_feature_switches();
    result = result + test_multi_macro();
    result = result + test_macro_init();
    result = result + test_include();
    result = result + test_func_like_macro();
    result = result + test_nested_macro_expand();
    result = result + test_do_while_0_macro();
    result = result + test_multiline_macro();
    result = result + test_if_elif_expr();
    
    return result;
}

/*=============================*
 * 十六、main函数
 *=============================*/

int main() {
    int result = test_all_pp_features();
    return result;
}
