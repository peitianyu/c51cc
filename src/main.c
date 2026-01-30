#ifdef MINITEST_IMPLEMENTATION
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