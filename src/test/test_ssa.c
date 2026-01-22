int max(int a, int b) {
    if (a > b)
        return a;
    else
        return b;
}

int main() {
    int x = 5;
    int y = 7;
    int m = max(x, y);

    return m;
}