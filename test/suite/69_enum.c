/* 69_enum: 枚举类型 */

enum Color {
    RED = 0,
    GREEN = 1,
    BLUE = 2,
    WHITE = 255
};

int color_value(int c) {
    switch (c) {
    case RED:   return 10;
    case GREEN: return 20;
    case BLUE:  return 30;
    case WHITE: return 40;
    default:    return 0;
    }
}

int main(void) {
    int r = 0;
    r = r + color_value(RED);     /* 10 */
    r = r + color_value(GREEN);   /* 20 */
    r = r + color_value(BLUE);    /* 30 */
    r = r + color_value(WHITE);   /* 40 */
    return r;                      /* 100 */
}
