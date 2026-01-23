int max(int a, int b) {
    int c = a;
    if (c > 1)
        c = a + 1;
    else
        c = b - 1;
    int d = c + 1;
    return d;
}

// int main() {
//     int x = 5;
//     int y = 7;
//     int m = max(x, y);

//     return m;
// }