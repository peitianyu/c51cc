/* 51_void_func: void函数和副作用 */

int g_x = 0;
int g_y = 0;

void add_to_g(int val) {
    g_x = g_x + val;
}

void set_gy(int val) {
    g_y = val;
}

int main(void) {
    add_to_g(10);
    add_to_g(20);
    add_to_g(30);
    set_gy(5);
    return g_x + g_y;  /* 60 + 5 = 65 */
}
