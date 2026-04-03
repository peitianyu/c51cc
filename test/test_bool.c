/* bit/bool 类型测试 */
/* 根据 Keil C51 约定，bool 类型通过 Carry Flag (C) 返回 */

bool is_positive(int x) {
    return x > 0;
}

bool is_zero(int x) {
    return x == 0;
}

bool is_negative(int x) {
    return x < 0;
}

/* 逻辑与 */
bool and_op(bool a, bool b) {
    return a && b;
}

/* 逻辑或 */
bool or_op(bool a, bool b) {
    return a || b;
}

/* 逻辑非 */
bool not_op(bool a) {
    return !a;
}

int main(void) {
    bool r1 = is_positive(5);
    bool r2 = is_zero(0);
    bool r3 = and_op(r1, r2);
    bool r4 = or_op(r1, r2);
    bool r5 = not_op(r1);
    return r1 + r2 + r3 + r4 + r5;
}
