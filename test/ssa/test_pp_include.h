/**
 * 预处理器 #include 测试头文件
 */

#ifndef TEST_PP_INCLUDE_H
#define TEST_PP_INCLUDE_H

// 从include文件定义的宏
#define INCLUDE_MACRO 42
#define INCLUDE_OFFSET 1000
#define INCLUDE_STR "included"

// 条件编译宏
#define INCLUDE_FEATURE_ENABLED

// 数组大小宏
#define INCLUDE_ARRAY_SIZE 8

// 用于测试的结构体定义
struct IncludeStruct {
    int x;
    int y;
};

// 从include文件声明的变量
extern int include_var;

// 从include文件声明的函数
int include_func(int a);

#endif /* TEST_PP_INCLUDE_H */
