// Instruction selection tests: data spaces and SFR/SBIT

register char P1 = 0x90;
register bool P1_0 = 0x90;

unsigned char data g_data = 1;
unsigned char idata g_idata = 2;
unsigned char xdata g_xdata = 3;
unsigned char code  g_code  = 4;

int touch_data(int v) {
    g_data = (unsigned char)v;
    return g_data;
}

int touch_idata(int v) {
    g_idata = (unsigned char)v;
    return g_idata;
}

int touch_xdata(int v) {
    g_xdata = (unsigned char)v;
    return g_xdata;
}

int touch_code(void) {
    return g_code;
}

int sfr_ops(int v) {
    P1 = (char)v;
    P1_0 = 1;
    if (P1_0) {
        P1 = (char)(P1 + 1);
    }
    return P1;
}

int main(void) {
    int a = 10;
    return touch_data(a)
         + touch_idata(a + 1)
         + touch_xdata(a + 2)
         + touch_code()
         + sfr_ops(a);
}
