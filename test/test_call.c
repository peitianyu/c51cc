int add3(int a, int b, int c) {
    return a + b + c;
}

int sum10(int a, int b, int c, int d, int e,
          int f, int g, int h, int i, int j) {
    int r = a + b + c + d + e;
    r = r + f + g + h + i + j;
    return r;
}

int caller(int x) {
    return sum10(1, 2, 3, 4, 5, 6, 7, 8, 9, x) + add3(x, 1, 2);
}

int main(void) {
    return caller(5);
}
