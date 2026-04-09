/* 71_ifdef_cond: 条件编译 */

#define FEATURE_A
#define VALUE_B 10

#ifdef FEATURE_A
int feat_a = 1;
#else
int feat_a = 0;
#endif

#ifndef FEATURE_C
int feat_c = 0;
#else
int feat_c = 1;
#endif

#if VALUE_B > 5
int val_check = 1;
#else
int val_check = 0;
#endif

int main(void) {
    return feat_a + feat_c + val_check;  /* 1 + 0 + 1 = 2 */
}
