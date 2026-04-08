unsigned char data  ac_data  = 0x10;
unsigned char idata ac_idata = 0x20;
unsigned char xdata ac_xdata = 0x30;
unsigned char code  ac_code  = 0x40;

unsigned char addrspace_read_data(unsigned data char *p) {
    return *p;
}

unsigned char addrspace_read_idata(unsigned idata char *p) {
    return *p;
}

unsigned char addrspace_bump_xdata(unsigned xdata char *p) {
    *p = *p + 1;
    return *p;
}

unsigned char addrspace_read_code(unsigned code char *p) {
    return *p;
}

int addrspace_calls_main(void) {
    return addrspace_read_data(&ac_data)
         + addrspace_read_idata(&ac_idata)
         + addrspace_bump_xdata(&ac_xdata)
         + addrspace_read_code(&ac_code);
}
int main()
{
    return addrspace_calls_main();
}