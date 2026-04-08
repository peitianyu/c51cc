/* Integer (2-byte) arithmetic tests for instruction selection */

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

int main()
{
    return add_int(1, 2) + sub_int(1, 2) + mul_int(3, 4) + div_int(10, 2) + mod_int(10, 3) +
           unsigned_add_int(1U, 2U) + neg_int(-42) + mixed_int(1, 2, 3);
}