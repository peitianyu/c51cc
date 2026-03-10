// Instruction selection tests: arithmetic/bit/shift/compare

// int ret_param(int x) {
//     return x;
// }

// char add_sub(char a, char b) {
//     return (a + b) ^ (a - b);
// }

// char add_ptr(char *p, char x) {
//     return *p + x;
// }

// int add_op(int a, int b) {
//     return a + b;
// }

// int sub_op(int a, int b) {
//     return a - b;
// }

// int mul_op(int a, int b) {
//     return a * b;
// }

// int div_op(int a, int b) {
//     return a / b;
// }

char mod_op(char a, char b) {
    return a % b;
}

// int mul_div_mod(int a, int b) {
//     return a * b + a / b + a % b;
// }

// unsigned int shl_shr(unsigned int v, int s) {
//     return (v << s) | (v >> s);
// }

// int logic_ops(int a, int b) {
//     return ~((a & b) | (a ^ b));
// }

// int cmp_ops(int a, int b) {
//     return (a == b) * 1
//          + (a != b) * 2
//          + (a <  b) * 4
//          + (a <= b) * 8
//          + (a >  b) * 16
//          + (a >= b) * 32;
// }

// int main(void) {
//     int a = 13;
//     int b = 5;
//     unsigned int v = 0x1234;
//     return add_sub(a, b)
//          + mul_div_mod(a, b)
//          + (int)shl_shr(v, 3)
//          + logic_ops(a, b)
//          + cmp_ops(a, b);
// }
