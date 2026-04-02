int shl_u8(int a, int b) {
    int v = a & 0xff;
    while (b > 0) {
        v = v * 2;
        b = b - 1;
    }
    return v & 0xff;
}

int shr_u8(int a, int b) {
    int v = a & 0xff;
    while (b > 0) {
        v = v / 2;
        b = b - 1;
    }
    return v & 0xff;
}

int cmp_ops(int a, int b) {
    int r = 0;
    if (!(a - b)) r = r + 1;
    if (a - b) r = r + 2;
    if (b > a)  r = r + 4;
    if (!(a > b)) r = r + 8;
    if (a > b)  r = r + 16;
    if (!(b > a)) r = r + 32;
    return r;
}

int bit_ops(int a, int b) {
    int x = (a & b) | (a ^ b);
    x = ~x;
    return x;
}

int main(void) {
    int a = 5;
    int b = 2;
    return shl_u8(a, b) + shr_u8(a, b) + cmp_ops(a, b) + bit_ops(a, b);
}
