#ifdef MINITEST_IMPLEMENTATION
#include "core/minitest.h"

int g_argc;
char **g_argv;
void main(int argc, char **argv) {
    RUN_ALL_TESTS(argc, argv);
}
#else 

#include "stdio.h"

int main() {
    printf("hello main\n");
    return 0;
}

#endif