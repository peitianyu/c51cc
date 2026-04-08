int shifts_int(int a, int s) { return (a << s) + (a >> s); }

int main()
{
    return shifts_int(42, 1) + shifts_int(-42, 1) + shifts_int(42, 2) + shifts_int(-42, 2) + shifts_int(42, 3) +
           shifts_int(-42, 3) + shifts_int(42, 4) + shifts_int(-42, 4) + shifts_int(42, 5) + shifts_int(-42, 5) +
           shifts_int(42, 6) + shifts_int(-42, 6) + shifts_int(42, 7) + shifts_int(-42, 7);
}