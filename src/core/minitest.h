#ifndef MINITEST_H
#define MINITEST_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef MINITEST_IMPLEMENTATION

typedef void (*TestFn)(void);
typedef struct { const char *name; TestFn fn; } Test;
extern int g_argc; 
extern char **g_argv;

/* ========== 平台适配：测试注册段 ========== */
#if defined(_WIN32)

/*
 * Windows / TCC-PE: ELF __start/__stop 段边界符号不可用。
 * 方案：所有 Test 结构放入 "tsec" section，利用 TCC 按编译单元
 * 顺序排列 section 数据的特性。
 * - __t_begin 定义在 main.c（第一个编译单元，通过 MINITEST_MAIN）
 * - __t_end   定义在 minitest_end.c（最后一个编译单元）
 * - 所有 TEST 宏定义的 Test 结构夹在两者之间
 */

extern const Test __t_begin;   /* 定义在 minitest_end.c */
extern const Test __t_end;     /* 定义在 minitest_end.c */

#ifdef MINITEST_MAIN
const Test __attribute__((section("tsec"))) __t_begin = { NULL, NULL };
#endif

#define TEST(suite, name)                                            \
    static void suite##_##name(void);                                \
    static const Test __attribute__((section("tsec")))               \
        __t_##suite##name = { #suite "." #name, suite##_##name };    \
    static void suite##_##name(void)

#define RUN_ALL_TESTS(argc, argv)                                           \
    do {                                                                    \
        g_argc = (argc);                                                    \
        g_argv = (argv);                                                    \
        const Test *b = &__t_begin + 1;                                     \
        const Test *e = &__t_end;                                           \
        size_t n = 0;                                                       \
        for (const Test *p = b; p < e; ++p) { if (p->fn) n++; }            \
        if (!n) { puts("No tests"); break; }                                \
        printf("\n===== Tests =====\n");                                    \
        size_t idx = 0;                                                     \
        for (const Test *p = b; p < e; ++p) {                               \
            if (p->fn) printf("%2zu : %s\n", ++idx, p->name);              \
        }                                                                   \
        printf("# (0=all, ENTER=quit): "); fflush(stdout);                 \
        int c = getchar();                                                  \
        if (c == '\n' || c == EOF) break;                                   \
        ungetc(c, stdin);                                                   \
        int k;  if (scanf("%d", &k) != 1) break;                            \
        while (getchar() != '\n');                                           \
        if (k < 0 || (size_t)k > n) { puts("Bad#"); break; }               \
        idx = 0;                                                            \
        for (const Test *p = b; p < e; ++p) {                               \
            if (!p->fn) continue;                                           \
            idx++;                                                          \
            if (k && idx != (size_t)k) continue;                            \
            printf("[ RUN ] %s\n", p->name); p->fn();                      \
            printf("[  OK ] %s\n", p->name);                                \
        }                                                                   \
    } while (0)

#else /* Linux / ELF */

#ifdef __TINYC__
__asm__(".global __start_testsec\n"
        "__start_testsec = .\n"
        ".global __stop_testsec\n"
        "__stop_testsec = .\n");
#undef __attribute__
#endif

extern void *__start_testsec;
extern void *__stop_testsec;

#define TEST(suite, name)                       \
    static void suite##_##name(void);           \
    static const Test __t_##suite##name         \
        __attribute__((section("testsec"))) = { \
            #suite "." #name, suite##_##name }; \
    static void suite##_##name(void)

#define RUN_ALL_TESTS(argc, argv)                                           \
    do {                                                                    \
        g_argc = (argc);                                                    \
        g_argv = (argv);                                                    \
        Test *b = (Test*)&__start_testsec, *e = (Test*)&__stop_testsec;     \
        size_t n = e - b;                                                   \
        if (!n) { puts("No tests"); break; }                                \
        printf("\n\033[36m===== Tests =====\033[0m\n");                     \
        for (size_t i = 0; i < n; ++i) printf("\033[33m%2zu\033[0m : %s\n", i + 1, b[i].name); \
        printf("\033[35m# (0=all, ENTER=quit): \033[0m"); fflush(stdout);   \
        int c = getchar();                                                  \
        if (c == '\n' || c == EOF) break;                                   \
        ungetc(c, stdin);                                                   \
        int k;  if (scanf("%d", &k) != 1) break;                            \
        while (getchar() != '\n');  /* 吃掉行尾 */                           \
        if (k < 0 || (size_t)k > n) { puts("\033[31mBad#\033[0m"); break; } \
        for (size_t i = (k ? k - 1 : 0), lim = (k ? i + 1 : n); i < lim; ++i) { \
            printf("\033[32m[ RUN ]\033[0m %s\n", b[i].name); b[i].fn();    \
            printf("\033[32m[  OK ]\033[0m %s\n", b[i].name);               \
        }                                                                   \
    } while (0)

#endif /* _WIN32 */

#define ASSERT(cond)      do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)
#define ASSERT_TRUE(x)    ASSERT(x)
#define ASSERT_EQ(a, b)   ASSERT((a) == (b))
#define ASSERT_STREQ(a,b) ASSERT(strcmp((a),(b)) == 0)

#else 

#define ASSERT(cond)      do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)
#define ASSERT_TRUE(x)    ASSERT(x)
#define ASSERT_EQ(a, b)   ASSERT((a) == (b))
#define ASSERT_STREQ(a,b) ASSERT(strcmp((a),(b)) == 0)
#define TEST(suite, name) static void suite##_##name(void)
#define RUN_ALL_TESTS(argc, argv) do{}while(0)

#endif 

#endif /* MINITEST_H */