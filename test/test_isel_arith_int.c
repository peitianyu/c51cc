// Integer (2-byte) arithmetic tests for instruction selection

int add_int(int a, int b) {
    return a + b;
}

int sub_int(int a, int b) {
    return a - b;
}

int mul_int(int a, int b) {
    return a * b;
}

int div_int(int a, int b) {
    return a / b;
}

int mod_int(int a, int b) {
    return a % b;
}

unsigned int unsigned_add_int(unsigned int a, unsigned int b) {
    return a + b;
}

int neg_int(int a) {
    return -a;
}

int mixed_int(int a, int b, int c) {
    return a * b + c - (a ^ b);
}

int shifts_int(int a, int s) {
    return (a << s) + (a >> s);
}
