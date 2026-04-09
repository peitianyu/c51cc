/* 13_if_else: if/else 分支 */

int abs_val(int x) {
    if (x < 0) {
        return -x;
    } else {
        return x;
    }
}

int main(void) {
    return abs_val(5) + abs_val(-7);  /* 5 + 7 = 12 */
}
