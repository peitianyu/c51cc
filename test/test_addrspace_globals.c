unsigned char data  ag_data  = 1;
unsigned char idata ag_idata = 2;
unsigned char xdata ag_xdata = 3;
unsigned char code  ag_code  = 4;

int addrspace_globals_read_all(void) {
    return ag_data + ag_idata + ag_xdata + ag_code;
}

int addrspace_globals_main(void) {
    return addrspace_globals_read_all();
}

int main()
{
    return 0;
}