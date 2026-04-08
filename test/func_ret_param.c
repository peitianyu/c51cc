char ret_param(char x) {
    return x;
}

int main()
{
    return ret_param(42) + ret_param(-1) + ret_param(127) + ret_param(-128);
}