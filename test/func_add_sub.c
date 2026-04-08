char add_sub(char a, char b) {
    return (a + b) ^ (a - b);
}

int main()
{
    return add_sub(1, 2) + add_sub(-1, -2) + add_sub(127, 1) + add_sub(-128, -1);
}