// Instruction selection tests: arithmetic/bit/shift/compare

int add_sub(int a, int b) {
    int c = a + b;
    int d = a - b;
    return c ^ d;
}

int mul_div_mod(int a, int b) {
    int m = a * b;
    int d = a / b;
    int r = a % b;
    return m + d + r;
}

unsigned int shl_shr(unsigned int v, int s) {
    unsigned int a = v << s;
    unsigned int b = v >> s;
    return a | b;
}

int logic_ops(int a, int b) {
    int x = (a & b) | (a ^ b);
    return ~x;
}

int cmp_ops(int a, int b) {
    int r = 0;
    if (a == b) r += 1;
    if (a != b) r += 2;
    if (a < b)  r += 4;
    if (a <= b) r += 8;
    if (a > b)  r += 16;
    if (a >= b) r += 32;
    return r;
}

int main(void) {
    int a = 13;
    int b = 5;
    unsigned int v = 0x1234;
    return add_sub(a, b)
         + mul_div_mod(a, b)
         + (int)shl_shr(v, 3)
         + logic_ops(a, b)
         + cmp_ops(a, b);
}
