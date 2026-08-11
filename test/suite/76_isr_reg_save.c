/* 76_isr_reg_save: 中断压栈保护 (硬件测试, 返回 0=通过)
 * 覆盖: ISR 内破坏 R0-R7, 返回后 main 寄存器值必须完整 (PUSH/POP 保护)。
 * 验证: main 中 a/b/c/d 若被 ISR 覆盖则 acc 错; 正确保存则 acc=0xAA+BB+CC+DD。
 */
typedef unsigned char u8;
typedef unsigned int  u16;

sfr AUXR = 0x8E;  sfr TCON = 0x88;  sfr TMOD = 0x89;
sfr TL0  = 0x8A;  sfr TH0  = 0x8C;
sfr IE   = 0xA8;  sfr P_SW2= 0xBA;  sfr WTST = 0xE9;
sbit T0x12 = AUXR ^ 7;
sbit TR0   = TCON ^ 4;
sbit EA    = IE   ^ 7;
sbit ET0   = IE   ^ 1;
sbit EAXFR = P_SW2 ^ 7;

volatile u16 t0_cnt = 0;

void Timer0_ISR(void) interrupt 1 {
    u8 x = 0x11, y = 0x22, z = 0x33, w = 0x44;  /* 破坏 R0-R7 */
    u16 s = 0x1234;
    t0_cnt++;
    s = s + x + y + z + w;              /* 用寄存器运算, 保持 t0_cnt 语义 */
}

int main(void) {
    u8  a = 0xAA, b = 0xBB, c = 0xCC, d = 0xDD;
    u16 acc;

    WTST = 0;
    EAXFR = 1;
    T0x12 = 1;
    TMOD = (TMOD & 0xF0) | 0x02;
    TH0 = 0xF0;
    TL0 = 0x00;
    t0_cnt = 0;
    ET0 = 1;  EA = 1;
    TR0 = 1;
    while (t0_cnt < 1);                 /* 等 1 次中断 (ISR 破坏寄存器) */
    TR0 = 0;  EA = 0;

    /* ISR 返回后 main 的 a/b/c/d 必须仍 = 0xAA/BB/CC/DD */
    acc = a + b + c + d;                /* 0xAA+0xBB+0xCC+0xDD = 0x030E */
    if (a != 0xAA || b != 0xBB || c != 0xCC || d != 0xDD) return 1;
    if (acc != 0x030E) return 2;
    if (t0_cnt != 1) return 3;
    return 0;
}
