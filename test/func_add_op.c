char add_op(char a, char b) {
    return a + b;
}

int main()
{
    return add_op(1, 2) + add_op(-1, -2) + add_op(127, 1) + add_op(-128, -1);
}