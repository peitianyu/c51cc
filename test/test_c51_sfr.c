/* test_c51_sfr.c - C51 SFR和存储类关键字测试
 * 测试 register/data/idata/xdata/code 关键字
 */

// ========== SFR声明 (register关键字) ==========
// register int -> sfr16 (16位SFR)
register int TCON = 0x88;     // 定时器控制寄存器

// register char -> sfr (8位SFR)  
register char P1 = 0x90;      // P1口
register char P0 = 0x80;      // P0口
register char PSW = 0xD0;     // 程序状态字

// register bool -> sbit (位SFR)
register bool EA = 0xA8;      // 中断总使能 (0xA8 -> 15H.0)
register bool TR0 = 0x88;     // T0运行控制 (0x88 -> 11H.0)

// ========== 存储类关键字测试 ==========
// data: 直接寻址内部RAM (00H-7FH)
data int data_var = 100;
data char data_buf[4];

// idata: 间接寻址内部RAM (00H-FFH)
idata int idata_var = 200;

// xdata: 外部RAM (0000H-FFFFH)
xdata int xdata_buffer = 300;
xdata char xdata_array[10];

// code: 代码/只读存储器
code char code_msg[] = "Hello";
code int code_table[] = {1, 2, 3, 4, 5};

// 默认存储类（data）
int normal_var = 500;

// ========== 中断函数 ==========
void interrupt_func(0, 1) {
    // 使用SFR
    P1 = 0xFF;
    EA = 1;
    TR0 = 1;
}

// ========== 测试函数 ==========
// 访问data段变量
int test_data(void) {
    data_var = data_var + 10;
    return data_var;
}

// 访问xdata段变量
int test_xdata(void) {
    xdata_buffer = xdata_buffer + 50;
    return xdata_buffer;
}

// 访问code段（只读）
int test_code(int idx) {
    return code_table[idx];
}

// 使用SFR
void test_sfr(void) {
    P0 = 0x00;
    P1 = 0xFF;
    PSW = 0x00;
}

// 主函数
int main(void) {
    int a, b, c;
    
    // 测试data段
    a = test_data();
    
    // 测试xdata段
    b = test_xdata();
    
    // 测试code段
    c = test_code(2);
    
    // 测试SFR
    test_sfr();
    
    // 计算结果
    normal_var = a + b + c;
    
    return normal_var;
}
