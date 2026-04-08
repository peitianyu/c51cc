int add3(int a, int b, int c) {
    return a + b + c;
}

int call_add() {
    int a = 10, b = 20, c = 30;
    return add3(a, b, c);
}

int main()
{
    return call_add();
}
