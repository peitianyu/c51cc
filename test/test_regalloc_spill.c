/* Register allocation spill test: live ranges across calls to force spills */

int helper_spill(int x) {
    int t = x * 3 + 7;
    t += (x >> 1);
    return t;
}

int reg_spill(int a) {
    int v1 = 1, v2 = 2, v3 = 3, v4 = 4, v5 = 5, v6 = 6, v7 = 7, v8 = 8;
    int acc = a + v1;

    /* Use values across calls to keep them live and force spilling */
    acc += v2;
    acc += helper_spill(v3);
    acc += v4;
    acc += helper_spill(v5 + acc);
    acc += v6;
    acc += v7 * v8;

    /* More math to lengthen live ranges */
    acc = acc * (v1 + v2 + v3) - (v4 + v5);
    return acc + a;
}
int main() 
{
    return 0;
}
