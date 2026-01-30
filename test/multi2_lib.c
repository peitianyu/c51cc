unsigned char buf[4] = {1, 2, 3, 4};

int sum_buf(void)
{
    int r = 0;
    r = r + buf[0];
    r = r + buf[1];
    r = r + buf[2];
    r = r + buf[3];
    return r;
}
