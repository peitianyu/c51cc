/* 38_struct_basic: 结构体基础 */

struct Point {
    int x;
    int y;
};

int dist_sq(struct Point *p) {
    return p->x * p->x + p->y * p->y;
}

int main(void) {
    struct Point p;
    p.x = 3;
    p.y = 4;
    return dist_sq(&p);  /* 9 + 16 = 25 */
}
