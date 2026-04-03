/* Register allocation stress test: many locals to create high register pressure */

int reg_more(int a) {
    int a1 = a + 1;
    int a2 = a1 + 2;
    int a3 = a2 + 3;
    int a4 = a3 + 4;
    int a5 = a4 + 5;
    int a6 = a5 + 6;
    int a7 = a6 + 7;
    int a8 = a7 + 8;
    int a9 = a8 + 9;
    int a10 = a9 + 10;
    int a11 = a10 + 11;
    int a12 = a11 + 12;
    int a13 = a12 + 13;
    int a14 = a13 + 14;
    int a15 = a14 + 15;
    int a16 = a15 + 16;

    int sum = a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8
            + a9 + a10 + a11 + a12 + a13 + a14 + a15 + a16;

    /* Keep some variables live across a dummy computation */
    sum += (a16 - a1) * (a8 + a4);
    return sum + a;
}

int main() 
{
    return 0;
}