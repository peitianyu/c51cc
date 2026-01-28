// 测试SFR声明（register关键字）
// register int -> sfr16, register char -> sfr, register bool -> sbit

register int TCON = 0x88;     // sfr16: 16位SFR，地址0x0088
register char P1 = 0x90;      // sfr: 8位SFR，地址0x90
register bool EA = 0xA8;      // sbit: 位SFR，地址0xA8 -> 字节0x15，位0

// 测试存储类关键字
data int data_var = 10;       // data段: 直接寻址内部RAM
idata char idata_var;         // idata段: 间接寻址内部RAM
xdata int xdata_var = 100;    // xdata段: 外部RAM
code char code_var = 50;      // code段: 代码/只读存储器

// 普通全局变量（默认data段）
int normal_var = 20;

// 中断函数（使用 interrupt_func 语法）
void interrupt_func(0, 1) {
    P1 = 0xFF;    // 写入SFR
    EA = 1;       // 使能中断
}

// 主函数
int main() {
    data_var = 5;
    normal_var = data_var + 10;
    return normal_var;
}
