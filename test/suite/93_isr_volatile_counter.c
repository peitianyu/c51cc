/* 93_isr_volatile_counter: ISR 内 volatile 计数器写回 SFR (硬件测试, 返回 0=通过) */
typedef unsigned char u8;
sfr P0=0x80; sfr P1=0x90; sfr IE=0xA8; sfr TCON=0x88; sfr TMOD=0x89;
sfr TL0=0x8A; sfr TH0=0x8C; sfr AUXR=0x8E; sfr P_SW2=0xBA; sfr WTST=0xE9;
sbit EA=IE^7; sbit ET0=IE^1; sbit TR0=TCON^4;
sbit T0x12=AUXR^7; sbit EAXFR=P_SW2^7;
volatile u8 t0_cnt = 0;
void T0_ISR(void) interrupt 1 { t0_cnt++; P1 = t0_cnt; }
int main(void) {
    WTST=0; EAXFR=1; T0x12=1;
    TMOD=0x02; TH0=0xF0; ET0=EA=1; TR0=1;
    while(t0_cnt<3);
    TR0=0; EA=0;
    if (t0_cnt!=3 || P1!=3) return 1;
    P0=P1; return (P0==3)?0:1;
}
