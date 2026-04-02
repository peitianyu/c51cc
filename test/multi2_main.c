extern unsigned char buf[4];
extern int sum_buf(void);

int main(void)
{
    int r = sum_buf();
    return r + buf[0];
}
