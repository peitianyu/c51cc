int cmp_signed(char a, char b) {
    int r = 0;
    if (a < b) r = r + 1;
    if (a <= b) r = r + 2;
    if (a > b) r = r + 4;
    if (a >= b) r = r + 8;
    return r;
}

int shr_signed(char a, int n) {
    char x = a;
    while (n > 0) {
        x = x >> 1;
        n = n - 1;
    }
    return x;
}

int main(void) {
    int r = 0;
    r = r + cmp_signed(-2, 1);
    r = r + cmp_signed(2, -1);
    r = r + cmp_signed(-3, -1);
    r = r + shr_signed(-4, 1);
    r = r + shr_signed(-8, 2);
    return r;
}
