int cmp_signed(char a, char b) {
    int r = 0;
    if (a < b) r = r + 1;
    if (a <= b) r = r + 2;
    if (a > b) r = r + 4;
    if (a >= b) r = r + 8;
    return r;
}
int main() {
    return cmp_signed(-2, 1);
}
