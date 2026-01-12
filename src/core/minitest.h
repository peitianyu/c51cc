#ifndef MINITEST_H
#define MINITEST_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef MINITEST_IMPLEMENTATION

__asm__(".global __start_testsec\n"
        "__start_testsec = .\n"
        ".global __stop_testsec\n"
        "__stop_testsec = .\n");

#ifdef __TINYC__
#undef __attribute__
#endif

extern void *__start_testsec;
extern void *__stop_testsec;
typedef void (*TestFn)(void);
typedef struct { const char *name; TestFn fn; } Test;
extern int g_argc; 
extern char **g_argv;
#define TEST(suite, name)                       \
    static void suite##_##name(void);           \
    static const Test __t_##suite##name         \
        __attribute__((section("testsec"))) = { \
            #suite "." #name, suite##_##name }; \
    static void suite##_##name(void)

#define ASSERT(cond)      do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)
#define ASSERT_TRUE(x)    ASSERT(x)
#define ASSERT_EQ(a, b)   ASSERT((a) == (b))
#define ASSERT_STREQ(a,b) ASSERT(strcmp((a),(b)) == 0)

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

#else 

#define ASSERT(cond)      do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)
#define ASSERT_TRUE(x)    ASSERT(x)
#define ASSERT_EQ(a, b)   ASSERT((a) == (b))
#define ASSERT_STREQ(a,b) ASSERT(strcmp((a),(b)) == 0)
#define TEST(suite, name) static void suite##_##name(void)
#define RUN_ALL_TESTS(argc, argv) do{}while(0)

#endif 

#endif /* MINITEST_H */