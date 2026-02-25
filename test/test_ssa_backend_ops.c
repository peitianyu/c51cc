int cmp_pack(int a, int b) {
    int r = 0;
    r += (a == b);
    r += (a != b);
    r += (a < b);
    r += (a <= b);
    r += (a > b);
    r += (a >= b);
    return r;
}

int arith_mix(int a, int b) {
    int m = a * b;
    int d = b ? (a / b) : 0;
    int k = b ? (a % b) : 0;
    int n = -a;
    return m + d + k + n;
}

int shift_mix(int x, int s) {
    int l = x << s;
    int r = x >> s;
    return l ^ r;
}

int select_mix(int a, int b, int c) {
    int x = (a > b) ? a : b;
    int y = (x > c) ? x : c;
    return y;
}

int cast_mix(char c, unsigned char uc) {
    int s = (int)c;
    int u = (int)uc;
    char t = (char)(s + u);
    return (int)t + s + u;
}

int ptr_mix(void) {
    int arr[4] = {3, 5, 7, 11};
    int* p = arr;
    return p[0] + p[1] + p[2] + p[3];
}

int loop_phi(int n) {
    int i = 0;
    int s = 0;
    while (i < n) {
        s = s + i;
        i = i + 1;
    }
    return s;
}

int main(void) {
    int r = 0;
    r += cmp_pack(7, 3);
    r += arith_mix(17, 5);
    r += shift_mix(0x1234, 2);
    r += select_mix(3, 9, 4);
    r += cast_mix(-7, 250);
    r += ptr_mix();
    r += loop_phi(6);
    return r;
}
