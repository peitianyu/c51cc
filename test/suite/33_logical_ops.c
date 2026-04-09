/* 33_logical_ops: 逻辑运算 && || ! */

int main(void) {
    int a = 5;
    int b = 0;
    int r = 0;

    if (a && b)  r = r + 1;    /* skip: 5&&0 = false */
    if (a || b)  r = r + 2;    /* +2: 5||0 = true */
    if (!b)      r = r + 4;    /* +4: !0 = true */
    if (!a)      r = r + 8;    /* skip: !5 = false */
    if (a && !b) r = r + 16;   /* +16: 5 && !0 = true */

    return r;  /* 2+4+16 = 22 */
}
