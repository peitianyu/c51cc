int cmp_signed_lt(int a,int b){ return a < b; }
int cmp_signed_le(int a,int b){ return a <= b; }
int cmp_signed_gt(int a,int b){ return a > b; }
int cmp_signed_ge(int a,int b){ return a >= b; }
int cmp_signed_eq(int a,int b){ return a == b; }
int cmp_signed_ne(int a,int b){ return a != b; }

int main()
{
    return cmp_signed_lt(-1, 0) + cmp_signed_le(-1, 0) + cmp_signed_gt(0, -1) + cmp_signed_ge(0, -1) +
           cmp_signed_eq(42, 42) + cmp_signed_ne(42, 43);
}