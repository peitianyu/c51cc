extern int g_val;
extern int add2(int a, int b);

int main(void)
{
    int r = add2(1, 2);
    r = r + g_val;
    return r;
}
