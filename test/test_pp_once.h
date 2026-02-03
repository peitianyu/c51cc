#pragma once

/*
 * 用于测试 #pragma once：本文件没有 include guard。
 * 如果 once 不生效，被重复 include 会导致结构体重复定义。
 */

struct OnceStruct {
    int a;
};

#define ONCE_MACRO 7
