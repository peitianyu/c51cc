unsigned char data  ap_data  = 0x11;
unsigned char idata ap_idata = 0x22;
unsigned char xdata ap_xdata = 0x33;
unsigned char code  ap_code  = 0x44;

unsigned data  char *ap_ptr_data;
unsigned idata char *ap_ptr_idata;
unsigned xdata char *ap_ptr_xdata;
unsigned code  char *ap_ptr_code;

int addrspace_pointers_main(void) {
    int sum = 0;

    ap_ptr_data = &ap_data;
    *ap_ptr_data = 0x55;
    sum += *ap_ptr_data;

    ap_ptr_idata = &ap_idata;
    *ap_ptr_idata = 0x66;
    sum += *ap_ptr_idata;

    ap_ptr_xdata = &ap_xdata;
    *ap_ptr_xdata = 0x77;
    sum += *ap_ptr_xdata;

    ap_ptr_code = &ap_code;
    sum += *ap_ptr_code;

    return sum;
}