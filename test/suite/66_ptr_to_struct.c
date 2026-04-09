/* 66_ptr_to_struct: 结构体指针 */

struct Point {
    int x;
    int y;
};

void init_point(struct Point *p, int x, int y) {
    p->x = x;
    p->y = y;
}

int sum_point(struct Point *p) {
    return p->x + p->y;
}

int main(void) {
    struct Point p1;
    struct Point p2;
    init_point(&p1, 10, 20);
    init_point(&p2, 30, 40);
    return sum_point(&p1) + sum_point(&p2);  /* 30 + 70 = 100 */
}
