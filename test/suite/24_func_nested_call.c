/* 24_func_nested_call: 嵌套函数调用 */

int double_val(int x) {
    return x + x;
}

int triple_val(int x) {
    return x + double_val(x);
}

int chain_call(int x) {
    return triple_val(double_val(x));
}

int main(void) {
    return chain_call(3);  /* double(3)=6, triple(6)=6+12=18 */
}
