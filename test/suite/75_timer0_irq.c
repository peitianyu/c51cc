/* 75_timer0_irq: Timer0 中断计数 (硬件测试, 返回 0=通过)
 * 覆盖: Timer0 配置 (1T, mode2 8位自动重装), 中断向量, ISR 入口/返回,
 *       volatile 跨中断共享变量, EA/ET0/TR0 使能。
 * 依赖 sim251 定时器/中断模型 (golden_timer 已证可用)。
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
    t0_cnt++;
}

int main(void) {
    WTST = 0;
    EAXFR = 1;
    T0x12 = 1;                          /* Timer0 1T */
    TMOD = (TMOD & 0xF0) | 0x02;        /* Timer0 mode 2 (8位自动重装) */
    TH0 = 0xF0;                         /* 重装 0xF0 → 每 16 周期溢出 */
    TL0 = 0x00;
    t0_cnt = 0;
    ET0 = 1;  EA = 1;
    TR0 = 1;                            /* 启动 */
    while (t0_cnt < 4);                 /* 等 4 次中断 */
    TR0 = 0;  EA = 0;
    return (t0_cnt == 4) ? 0 : 1;
}
