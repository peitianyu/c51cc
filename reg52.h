#ifndef __REG52_H__
#define __REG52_H__

#define _nop_() ((void)0)
#define _crol_(value, shift) ((unsigned char)((((unsigned char)(value)) << ((shift) & 7)) | (((unsigned char)(value)) >> ((8 - ((shift) & 7)) & 7))))

register char         P0          =           0x80;
    register bool    P00         =           P0^0;
    register bool    P01         =           P0^1;
    register bool    P02         =           P0^2;
    register bool    P03         =           P0^3;
    register bool    P04         =           P0^4;
    register bool    P05         =           P0^5;
    register bool    P06         =           P0^6;
    register bool    P07         =           P0^7;

register char         SP          =           0x81;
register char         DPL         =           0x82;
register char         DPH         =           0x83;
register char         PCON        =           0x87;

register char         TCON        =           0x88;
    register bool    TF1         =           TCON^7;
    register bool    TR1         =           TCON^6;
    register bool    TF0         =           TCON^5;
    register bool    TR0         =           TCON^4;
    register bool    IE1         =           TCON^3;
    register bool    IT1         =           TCON^2;
    register bool    IE0         =           TCON^1;
    register bool    IT0         =           TCON^0;

register char         TMOD        =           0x89;
register char         TL0         =           0x8A;
register char         TL1         =           0x8B;
register char         TH0         =           0x8C;
register char         TH1         =           0x8D;
register char         AUXR        =           0x8E;

register char         P1          =           0x90;
    register bool    P10         =           P1^0;
    register bool    P11         =           P1^1;
    register bool    P12         =           P1^2;
    register bool    P13         =           P1^3;
    register bool    P14         =           P1^4;
    register bool    P15         =           P1^5;
    register bool    P16         =           P1^6;
    register bool    P17         =           P1^7;
    register bool    T2EX        =           P1^1;
    register bool    T2          =           P1^0;

register char         SCON        =           0x98;
    register bool    SM0         =           SCON^7;
    register bool    SM1         =           SCON^6;
    register bool    SM2         =           SCON^5;
    register bool    REN         =           SCON^4;
    register bool    TB8         =           SCON^3;
    register bool    RB8         =           SCON^2;
    register bool    TI          =           SCON^1;
    register bool    RI          =           SCON^0;

register char         SBUF        =           0x99;

register char         P2          =           0xA0;
    register bool    P20         =           P2^0;
    register bool    P21         =           P2^1;
    register bool    P22         =           P2^2;
    register bool    P23         =           P2^3;
    register bool    P24         =           P2^4;
    register bool    P25         =           P2^5;
    register bool    P26         =           P2^6;
    register bool    P27         =           P2^7;

register char         AUXR1       =           0xA2;

register char         IE          =           0xA8;
    register bool    EA          =           IE^7;
    register bool    EC          =           IE^6;
    register bool    ET2         =           IE^5;
    register bool    ES          =           IE^4;
    register bool    ET1         =           IE^3;
    register bool    EX1         =           IE^2;
    register bool    ET0         =           IE^1;
    register bool    EX0         =           IE^0;

register char         SADDR       =           0xA9;

register char         P3          =           0xB0;
    register bool    P30         =           P3^0;
    register bool    P31         =           P3^1;
    register bool    P32         =           P3^2;
    register bool    P33         =           P3^3;
    register bool    P34         =           P3^4;
    register bool    P35         =           P3^5;
    register bool    P36         =           P3^6;
    register bool    P37         =           P3^7;
    register bool    RD          =           P3^7;
    register bool    WR          =           P3^6;
    register bool    T1          =           P3^5;
    register bool    T0          =           P3^4;
    register bool    INT1        =           P3^3;
    register bool    INT0        =           P3^2;
    register bool    TXD         =           P3^1;
    register bool    RXD         =           P3^0;

register char         IPH         =           0xB7;
register char         IP          =           0xB8;
    register bool    PT2         =           IP^5;
    register bool    PS          =           IP^4;
    register bool    PT1         =           IP^3;
    register bool    PX1         =           IP^2;
    register bool    PT0         =           IP^1;
    register bool    PX0         =           IP^0;

register char         SADEN       =           0xB9;

register char         XICON       =           0xC0;
    register bool    PX3         =           XICON^7;
    register bool    EX3         =           XICON^6;
    register bool    IE3         =           XICON^5;
    register bool    IT3         =           XICON^4;
    register bool    PX2         =           XICON^3;
    register bool    EX2         =           XICON^2;
    register bool    IE2         =           XICON^1;
    register bool    IT2         =           XICON^0;

register char         T2CON       =           0xC8;
    register bool    TF2         =           T2CON^7;
    register bool    EXF2        =           T2CON^6;
    register bool    RCLK        =           T2CON^5;
    register bool    TCLK        =           T2CON^4;
    register bool    EXEN2       =           T2CON^3;
    register bool    TR2         =           T2CON^2;
    register bool    C_T2        =           T2CON^1;
    register bool    CP_RL2      =           T2CON^0;

register char         T2MOD       =           0xC9;
register char         RCAP2L      =           0xCA;
register char         RCAP2H      =           0xCB;
register char         TL2         =           0xCC;
register char         TH2         =           0xCD;

register char         PSW         =           0xD0;
    register bool    CY          =           PSW^7;
    register bool    AC          =           PSW^6;
    register bool    F0          =           PSW^5;
    register bool    RS1         =           PSW^4;
    register bool    RS0         =           PSW^3;
    register bool    OV          =           PSW^2;
    register bool    F1          =           PSW^1;
    register bool    P           =           PSW^0;

register char         ACC         =           0xE0;
register char         WDT_CONTR   =           0xE1;
register char         ISP_DATA    =           0xE2;
register char         ISP_ADDRH   =           0xE3;
register char         ISP_ADDRL   =           0xE4;
register char         ISP_CMD     =           0xE5;
register char         ISP_TRIG    =           0xE6;
register char         ISP_CONTR   =           0xE7;

register char         P4          =           0xE8;
    register bool    P40         =           P4^0;
    register bool    P41         =           P4^1;
    register bool    P42         =           P4^2;
    register bool    P43         =           P4^3;
    register bool    P44         =           P4^4;
    register bool    P45         =           P4^5;
    register bool    P46         =           P4^6;
    register bool    P47         =           P4^7;

register char         B           =           0xF0;

#endif
