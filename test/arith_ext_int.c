int add_overflow_signed(int a,int b){ return a + b; }
unsigned int add_overflow_unsigned(unsigned int a,unsigned int b){ return a + b; }

int add_with_const(int a){ return a + 32767; }
unsigned int addu_with_const(unsigned int a){ return a + (unsigned int)65535; }

int sub_borrow_signed(int a,int b){ return a - b; }
unsigned int sub_borrow_unsigned(unsigned int a,unsigned int b){ return a - b; }

int mul_signed(int a,int b){ return a * b; }
unsigned int mul_unsigned(unsigned int a,unsigned int b){ return a * b; }

int div_signed(int a,int b){ return a / b; }
int mod_signed(int a,int b){ return a % b; }
unsigned int div_unsigned(unsigned int a,unsigned int b){ return a / b; }
unsigned int mod_unsigned(unsigned int a,unsigned int b){ return a % b; }

int shl_int(int a,int c){ return a << c; }
int shr_signed(int a,int c){ return a >> c; }
unsigned int shr_unsigned(unsigned int a,int c){ return a >> c; }

int mixed_signed_unsigned(int a,unsigned int b){ return a + b; }
unsigned int mixed_unsigned_signed(unsigned int a,int b){ return a + b; }

int add_min_max(){ return 32767 + 1; }
int sub_min_max(){ return (-32768) - 1; }


int main()
{
    return add_overflow_signed(32767, 1) + add_overflow_unsigned(32767, 1) +
           add_with_const(0) + addu_with_const(0) +
           sub_borrow_signed(-32768, 1) + sub_borrow_unsigned(0, 1) +
           mul_signed(32767, 2) + mul_unsigned(65535, 2) +
           div_signed(-32768, -1) + mod_signed(-32768, -1) +
           div_unsigned(32767, 2) + mod_unsigned(32767, 2) +
           shl_int(1, 31) + shr_signed(-1, 31) + shr_unsigned(32767, 31) +
           mixed_signed_unsigned(-32768, 32767) + mixed_unsigned_signed(32767, -32768) +
           add_min_max() + sub_min_max();
}
