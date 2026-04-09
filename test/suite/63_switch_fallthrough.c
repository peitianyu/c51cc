/* 63_switch_fallthrough: switch落空(fallthrough) */

int test_switch(int x) {
    int r = 0;
    switch (x) {
    case 1:
        r = r + 1;
        /* fall through */
    case 2:
        r = r + 2;
        break;
    case 3:
        r = r + 4;
        break;
    default:
        r = r + 8;
        break;
    }
    return r;
}

int main(void) {
    int r = 0;
    r = r + test_switch(1);   /* 1+2=3 (fallthrough) */
    r = r + test_switch(2);   /* 2 */
    r = r + test_switch(3);   /* 4 */
    r = r + test_switch(99);  /* 8 */
    return r;                  /* 3+2+4+8 = 17 */
}
