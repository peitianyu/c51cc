char sub_op(char a, char b) {
    return a - b;
}

int main()
{
    return sub_op(1, 2) + sub_op(-1, -2) + sub_op(127, 1) + sub_op(-128, -1);
}