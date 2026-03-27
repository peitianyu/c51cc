/*
 * minitest_end.c — Windows TCC 下 minitest 段结束标记
 * 此文件必须作为编译命令中的 **最后一个** 源文件，
 * 以确保 __t_end 位于 "tsec" section 的末尾。
 * Linux/ELF 编译时此文件无任何作用。
 */
#ifdef MINITEST_IMPLEMENTATION
#ifdef _WIN32

typedef void (*TestFn)(void);
typedef struct { const char *name; TestFn fn; } Test;

const Test __attribute__((section("tsec"))) __t_end = { (void*)0, (void*)0 };

#endif
#endif
