// ssa_attr test: const/unsigned/volatile/data/noreturn

volatile unsigned int gv_vol = 1;
const unsigned int gv_const = 5;
unsigned int gv_u = 7;

// data/xdata/idata/code 关键字为C51扩展
unsigned int data gv_data = 3;

noreturn void must_exit(void) {
    while (1) {
        gv_vol++;
    }
}

int main(void) {
    unsigned int a = gv_const + gv_u;    // const global load folding
    unsigned int b = a >> 1;             // unsigned shift
    gv_vol = gv_vol + 1;                 // volatile should not be removed
    gv_data = gv_data + b;               // addrspace pass-through

    if (b > 10) {
        must_exit();                     // noreturn call should end block
        a = 0x1234;                      // unreachable
    }

    return (int)a;
}
