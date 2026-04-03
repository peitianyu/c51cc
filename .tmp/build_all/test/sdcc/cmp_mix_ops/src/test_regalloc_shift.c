int reg_shift(int a, int b) {
    int x1 = a + 3;
    int x2 = b + 5;
    int x3 = x1 + x2;
    int x4 = x3 + 7;
    int x5 = x4 + 9;
    int s1 = x5 << 1;
    int s2 = x4 >> 1;
    int s3 = x3 << (a & 3);
    int s4 = x5 >> (b & 3);
    int s5 = (s1 + s2) << 2;
    int s6 = (s3 - s4) >> 1;
    return x1 + x2 + x3 + x4 + x5 + s1 + s2 + s3 + s4 + s5 + s6;
}

int main() 
{
    return 0;
}