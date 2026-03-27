#ifdef MINITEST_IMPLEMENTATION
#define MINITEST_MAIN  /* Windows: 在此定义 __t_begin 和全局存储 */
#include "core/minitest.h"

int g_argc;
char **g_argv;
int main(int argc, char **argv) {
    RUN_ALL_TESTS(argc, argv);
    return 0;
}
#else 

#include "stdio.h"

int main() {
    printf("hello main\n");
    return 0;
}

#endif