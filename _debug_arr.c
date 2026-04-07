unsigned char test_arr_init(unsigned char idx)
{
    unsigned char rowMask[4] = {0xFE, 0xFD, 0xFB, 0xF7};
    return rowMask[idx];
}
