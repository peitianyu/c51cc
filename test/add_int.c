int add_int(int a, int b) { return a + b; }

int main() {
    int x = 5;
    int y = 10;
    int z = add_int(x, y);
    return z; // expect 15
}