/* 90_multi_isr: Timer0 + Timer1 双中断 (硬件测试, 返回 0=通过) */
typedef unsigned char u8;
typedef unsigned int u16;

sfr AUXR=0x8E; sfr TCON=0x88; sfr TMOD=0x89; sfr IE=0xA8;
sfr TL0=0x8A; sfr TH0=0x8C; sfr TL1=0x8B; sfr TH1=0x8D;
sfr P_SW2=0xBA; sfr WTST=0xE9;
sbit EA=IE^7; sbit ET0=IE^1; sbit ET1=IE^3;
sbit TR0=TCON^4; sbit TR1=TCON^6;
sbit T0x12=AUXR^7; sbit T1x12=AUXR^6; sbit EAXFR=P_SW2^7;

volatile u8 t0_cnt, t1_cnt;
void T0_ISR(void) interrupt 1 { t0_cnt++; }
void T1_ISR(void) interrupt 3 { t1_cnt++; }

int main(void) {
    WTST=0; EAXFR=1; T0x12=1; T1x12=1;
    TMOD=0x22; TH0=0xFC; TH1=0xFC;
    t0_cnt=t1_cnt=0; ET0=ET1=1; EA=1;
    TR0=TR1=1;
    while(t0_cnt<2 || t1_cnt<2);
    TR0=TR1=0; EA=0;
    return (t0_cnt>=2 && t1_cnt>=2) ? 0 : 1;
}
