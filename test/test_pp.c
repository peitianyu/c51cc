#define MAX_SIZE 100
#define MIN_SIZE 10

int a = MAX_SIZE;
int b = MIN_SIZE;

#ifdef DEBUG
int debug_mode = 1;
#else
int debug_mode = 0;
#endif

#ifndef TEST_FLAG
#define TEST_FLAG 42
#endif

int c = TEST_FLAG;

#define SQUARE(x) ((x) * (x))

int d = SQUARE(5);
