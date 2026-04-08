int sub_int(int a, int b) { return a - b; }

int main()
{
    return sub_int(1, 2) + sub_int(-1, -2) + sub_int(127, 1) + sub_int(-128, -1);
}