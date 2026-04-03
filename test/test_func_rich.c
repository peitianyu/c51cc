/* Rich function-oriented codegen test for C51 backend. */

int ret_const(void) {
    return 7;
}

int inc1(int x) {
    return x + 1;
}

int add2(int a, int b) {
    int sum = a + b;
    return sum;
}

int mix3(int a, int b, int c) {
    int t = add2(a, b);
    return t + c;
}

int sum6(int a, int b, int c, int d, int e, int f) {
    int sum = a + b + c;
    sum = sum + d + e + f;
    return sum;
}

int choose_value(int x) {
    if (x > 10) {
        return x - 3;
    }
    if (x > 5) {
        return x + 2;
    }
    return x + 9;
}

int double_inc(int x) {
    int first = inc1(x);
    int second = inc1(first);
    return second;
}

int nested_calls(int x) {
    return sum6(
        inc1(x),
        add2(x, 2),
        mix3(x, 1, 2),
        choose_value(x),
        ret_const(),
        double_inc(x));
}

int ptr_mix(int *left, int *right) {
    int a = *left;
    int b = *right;
    return add2(a, b) + inc1(a);
}

int keep_live_across_calls(int base) {
    int a = base + 1;
    int b = base + 2;
    int c = base + 3;
    int call_res = sum6(a, b, c, inc1(base), choose_value(base), ret_const());
    return call_res + a + b + c;
}

int main(void) {
    int x = 6;
    int y = 9;
    int total = 0;

    total = total + nested_calls(x);
    total = total + ptr_mix(&x, &y);
    total = total + keep_live_across_calls(4);
    total = total + mix3(3, 4, 5);
    total = total + choose_value(12);

    return total;
}