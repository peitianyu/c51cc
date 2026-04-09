/* 56_spill_across_call: 跨函数调用的寄存器溢出 */

int helper(int x) {
    return x + 1;
}

int main(void) {
    int a = 10;
    int b = 20;
    int c = helper(a);   /* 函数调用可能破坏寄存器, b需要保存 */
    int d = helper(b);   /* a,c需要保存 */
    return a + b + c + d; /* 10+20+11+21 = 62 */
}
