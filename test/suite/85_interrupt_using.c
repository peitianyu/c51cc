/* 85_interrupt_using: ISR 用寄存器组 (硬件测试, 返回 0=通过)
 * 覆盖: interrupt 1 using N (寄存器组切换), T0 定时器触发 ISR, volatile flag。
 * STC32G Timer0 ISR 典型用法 — using 修饰符指定寄存器组。
 */
typedef unsigned char u8;
typedef unsigned int  u16;

sfr AUXR  = 0x8E;  sfr TCON = 0x88;  sfr TMOD = 0x89;  sfr IE = 0xA8;
sfr TL0   = 0x8A;  sfr TH0  = 0x8C;  sfr P_SW2 = 0xBA; sfr WTST = 0xE9;
sbit T0x12 = AUXR ^ 7;
sbit TR0   = TCON ^ 4;
sbit EA    = IE   ^ 7;
sbit ET0   = IE   ^ 1;
sbit EAXFR = P_SW2 ^ 7;

volatile u8 t0_flag = 0;

void Timer0_ISR(void) interrupt 1 using 1 {
    t0_flag++;
}

int main(void) {
    WTST = 0;
    EAXFR = 1;
    T0x12 = 1;
    TMOD = (TMOD & 0xF0) | 0x02;
    TH0 = 0xFF;  TL0 = 0x00;
    ET0 = 1;  EA = 1;
    t0_flag = 0;
    TR0 = 1;
    while (!t0_flag);
    TR0 = 0;  EA = 0;
    return (t0_flag == 1) ? 0 : 1;
}
