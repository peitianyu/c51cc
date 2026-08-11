/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"STC32G_SPI.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_UART.h"
#include	"STC32G_Delay.h"
#include	"STC32G_Switch.h"

/*************   功能说明   ***************

通过高速SPI对PM25LV040/W25X40CL/W25Q80BV进行读写测试。

串口发指令对FLASH做扇区擦除、写入、读出的操作，命令指定地址。

默认波特率:  115200,8,N,1. 可以在"串口初始化函数"里修改.

串口命令设置: (字母不区分大小写)
    E 0x001234              --> 扇区擦除，指定十六进制地址.
    W 0x001234 1234567890   --> 写入操作，指定十六进制地址，后面为写入内容.
    R 0x001234 10           --> 读出操作，指定十六进制地址，后面为读出字节. 
    C                       --> 如果检测不到PM25LV040/W25X40CL/W25Q80BV, 发送C强制允许操作.

注意：为了通用，程序不识别地址是否有效，用户自己根据具体的型号来决定。

下载时, 选择时钟 24MHz (用户可在"config.h"修改频率).

******************************************/


/*************	本地常量声明	**************/

#define BUF_LENGTH          107			//n+1
#define EE_BUF_LENGTH       50      //

/******************* FLASH相关定义 ************************/
#define SFC_WREN        0x06        //串行Flash命令集
#define SFC_WRDI        0x04
#define SFC_RDSR        0x05
#define SFC_WRSR        0x01
#define SFC_READ        0x03
#define SFC_FASTREAD    0x0B
#define SFC_RDID        0xAB
#define SFC_PAGEPROG    0x02
#define SFC_RDCR        0xA1
#define SFC_WRCR        0xF1
#define SFC_SECTORER1   0xD7        //PM25LV040 扇区擦除指令
#define SFC_SECTORER2   0x20        //W25Xxx 扇区擦除指令
#define SFC_BLOCKER     0xD8
#define SFC_CHIPER      0xC7

sbit    SPI_CE  = P2^2;     //PIN1
sbit    SPI_SO  = P2^4;     //PIN2
sbit    SPI_SI  = P2^3;     //PIN5
sbit    SPI_SCK = P2^5;     //PIN6

#define SPI_CE_High()   SPI_CE  = 1     // set CE high
#define SPI_CE_Low()    SPI_CE  = 0     // clear CE low

/*************	本地变量声明	**************/

u8  sst_byte;
u32 Flash_addr;

u8  B_FlashOK;                                //Flash状态
u8  FLASH_ID, FLASH_ID1, FLASH_ID2;

/*************	本地函数声明	**************/

void    FlashCheckID(void);
void    RX2_Check(void);
u8      CheckFlashBusy(void);
void    FlashWriteEnable(void);
void    FlashChipErase(void);
void    FlashSectorErase(u32 addr);
void    SPI_Read_Nbytes( u32 addr, u8 *buffer, u16 size);
u8      SPI_Read_Compare(u32 addr, u8 *buffer, u16 size);
void    SPI_Write_Nbytes(u32 addr, u8 *buffer,  u8 size);

/*************  外部函数和变量声明 *****************/


/******************** IO口配置 ********************/
void GPIO_config(void)
{
	P2_MODE_IO_PU(GPIO_Pin_All);		//P2 设置为准双向口
	P4_MODE_IO_PU(GPIO_Pin_6 | GPIO_Pin_7);		//P4.6,P4.7 设置为准双向口
	P2_SPEED_HIGH(GPIO_Pin_2 | GPIO_Pin_3 | GPIO_Pin_4 | GPIO_Pin_5); //电平转换速度快（提高IO口翻转速度）

	SPI_SW(SPI_P22_P23_P24_P25);	//SPI_P54_P13_P14_P15,SPI_P22_P23_P24_P25,SPI_P54_P40_P41_P43,SPI_P35_P34_P33_P32
	UART2_SW(UART2_SW_P46_P47);		//UART2_SW_P10_P11,UART2_SW_P46_P47

	SPI_SCK = 0;    //设置SPI接口初始化电平
	SPI_SI = 1;
	SPI_CE = 1;
}

/******************** SPI 配置 ********************/
void SPI_config(void)
{
	SPI_InitTypeDef		SPI_InitStructure;

	SPI_InitStructure.SPI_Enable    = ENABLE;				//SPI启动    ENABLE, DISABLE
	SPI_InitStructure.SPI_SSIG      = ENABLE;				//片选位     ENABLE(忽略SS引脚功能), DISABLE(SS确定主机从机)
	SPI_InitStructure.SPI_FirstBit  = SPI_MSB;				//移位方向   SPI_MSB, SPI_LSB
	SPI_InitStructure.SPI_Mode      = SPI_Mode_Master;		//主从选择   SPI_Mode_Master, SPI_Mode_Slave
	SPI_InitStructure.SPI_CPOL      = SPI_CPOL_High;		//时钟相位   SPI_CPOL_High,   SPI_CPOL_Low
	SPI_InitStructure.SPI_CPHA      = SPI_CPHA_2Edge;		//数据边沿   SPI_CPHA_1Edge,  SPI_CPHA_2Edge
	SPI_InitStructure.SPI_Speed     = SPI_Speed_4;			//SPI速度    SPI_Speed_4, SPI_Speed_8, SPI_Speed_16, SPI_Speed_2
	SPI_Init(&SPI_InitStructure);
	NVIC_SPI_Init(DISABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
	SPI_ClearFlag();   //清除 SPIF和WCOL 标志
}

/******************** UART 配置 ********************/
void UART_config(void)
{
	COMx_InitDefine COMx_InitStructure;				//结构定义

	COMx_InitStructure.UART_Mode      = UART_8bit_BRTx;		//模式,   UART_ShiftRight,UART_8bit_BRTx,UART_9bit,UART_9bit_BRTx
//	COMx_InitStructure.UART_BRT_Use   = BRT_Timer2;			//选择波特率发生器, BRT_Timer2 (注意: 串口2固定使用BRT_Timer2, 所以不用选择)
	COMx_InitStructure.UART_BaudRate  = 115200ul;			//波特率,     110 ~ 115200
	COMx_InitStructure.UART_RxEnable  = ENABLE;				//接收允许,   ENABLE 或 DISABLE
	UART_Configuration(UART2, &COMx_InitStructure);		//初始化串口2 UART1,UART2,UART3,UART4
	NVIC_UART2_Init(ENABLE,Priority_1);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

u8  Hex2Ascii(u8 dat)
{
    dat &= 0x0f;
    if(dat < 10)    return (dat+'0');
    return (dat-10+'A');
}

/**********************************************/
void main(void)
{
    WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
    EAXSFR();		//扩展SFR(XFR)访问使能 
    CKCON = 0;      //提高访问XRAM速度

    GPIO_config();
    UART_config();
    SPI_config();
    EA = 1;

    PrintString2("命令设置:\r\n");
    PrintString2("E 0x001234            --> 扇区擦除\xfd  十六进制地址\r\n");
    PrintString2("W 0x001234 1234567890 --> 写入操作  十六进制地址  写入内容\r\n");
    PrintString2("R 0x001234 10         --> 读出操作  十六进制地址  读出字节\r\n");
    PrintString2("C                     --> 如果检测不到PM25LV040/W25X40CL/W25Q80BV, 发送C强制允许操作.\r\n\r\n");

    FlashCheckID();
    FlashCheckID();
    if(!B_FlashOK)  PrintString2("未检测到PM25LV040/W25X40CL/W25Q80BV!\r\n");
    else
    {
        if(B_FlashOK == 1)
        {
            PrintString2("检测到PM25LV040!\r\n");
        }
        else if(B_FlashOK == 2)
        {
            PrintString2("检测到W25X40CL!\r\n");
        }
        else if(B_FlashOK == 3)
        {
            PrintString2("检测到W25Q80BV!\r\n");
        }
        else if(B_FlashOK == 4)
        {
            PrintString2("检测到W25Q128FV!\r\n");
        }
    }
    PrintString2("制造商ID1 = 0x");
    TX2_write2buff(Hex2Ascii(FLASH_ID1 >> 4));
    TX2_write2buff(Hex2Ascii(FLASH_ID1));
    PrintString2("\r\n      ID2 = 0x");
    TX2_write2buff(Hex2Ascii(FLASH_ID2 >> 4));
    TX2_write2buff(Hex2Ascii(FLASH_ID2));
    PrintString2("\r\n   设备ID = 0x");
    TX2_write2buff(Hex2Ascii(FLASH_ID >> 4));
    TX2_write2buff(Hex2Ascii(FLASH_ID));
    PrintString2("\r\n");

    while (1)
    {
        delay_ms(1);
        if(COM2.RX_TimeOut > 0)
        {
            if(--COM2.RX_TimeOut == 0)  //超时,则串口接收结束
            {
                if(COM2.RX_Cnt > 0)
                {
                    RX2_Check();    //串口数据处理
                }
                COM2.RX_Cnt = 0;
            }
        }
    }
}

/**************** ASCII码转BIN ****************************/
u8  CheckData(u8 dat)
{
    if((dat >= '0') && (dat <= '9'))        return (dat-'0');
    if((dat >= 'A') && (dat <= 'F'))        return (dat-'A'+10);
    return 0xff;
}

/**************** 获取写入地址 ****************************/
u32 GetAddress(void)
{
    u32 address;
    u8  i,j;
    
    address = 0;
    if((RX2_Buffer[2] == '0') && (RX2_Buffer[3] == 'X'))
    {
        for(i=4; i<10; i++)
        {
            j = CheckData(RX2_Buffer[i]);
            if(j >= 0x10)   return 0x80000000;  //error
            address = (address << 4) + j;
        }
        return (address);
    }
    return  0x80000000; //error
}

/**************** 获取要读出数据的字节数 ****************************/
u8  GetDataLength(void)
{
    u8  i;
    u8  length;
    
    length = 0;
    for(i=11; i<COM2.RX_Cnt; i++)
    {
        if(CheckData(RX2_Buffer[i]) >= 10)  break;
        length = length * 10 + CheckData(RX2_Buffer[i]);
    }
    return (length);
}


/**************** 串口2处理函数 ****************************/

void RX2_Check(void)
{
    u8  i,j;
    u8  tmp[EE_BUF_LENGTH];

    if((COM2.RX_Cnt == 1) && (RX2_Buffer[0] == 'C'))    //发送C强制允许操作
    {
        B_FlashOK = 1;
        PrintString2("强制允许操作FLASH!\r\n");
    }

    if(!B_FlashOK)
    {
        PrintString2("PM25LV040/W25X40CL/W25Q80BV不存在, 不能操作FLASH!\r\n");
        return;
    }
    
    F0 = 0;
    if((COM2.RX_Cnt >= 10) && (RX2_Buffer[1] == ' '))   //最短命令为10个字节
    {
//			printf("收到内容如下： ");
//			for(i=0; i<COM2.RX_Cnt; i++)    printf("%c", RX2_Buffer[i]);    //把收到的数据原样返回,用于测试
//			printf("\r\n");

        for(i=0; i<10; i++)
        {
            if((RX2_Buffer[i] >= 'a') && (RX2_Buffer[i] <= 'z'))    RX2_Buffer[i] = RX2_Buffer[i] - 'a' + 'A';//小写转大写
        }
        Flash_addr = GetAddress();
        if(Flash_addr < 0x80000000)
        {
            if(RX2_Buffer[0] == 'E')    //擦除
            {
                FlashSectorErase(Flash_addr);
                PrintString2("已擦除\xfd一个扇区内容!\r\n");
                F0 = 1;
            }

            else if((RX2_Buffer[0] == 'W') && (COM2.RX_Cnt >= 12) && (RX2_Buffer[10] == ' '))   //写入N个字节
            {
                j = COM2.RX_Cnt - 11;
                for(i=0; i<j; i++)  tmp[i] = 0xff;      //检测要写入的空间是否为空
                i = SPI_Read_Compare(Flash_addr,tmp,j);
                if(i > 0)
                {
                    PrintString2("要写入的地址为非空,不能写入,请先擦除\xfd!\r\n");
                }
                else
                {
                    SPI_Write_Nbytes(Flash_addr,&RX2_Buffer[11],j);     //写N个字节 
                    i = SPI_Read_Compare(Flash_addr,&RX2_Buffer[11],j); //比较写入的数据
                    if(i == 0)
                    {
                        PrintString2("已写入");
                        if(j >= 100)    {TX2_write2buff((u8)(j/100+'0'));   j = j % 100;}
                        if(j >= 10)     {TX2_write2buff((u8)(j/10+'0'));    j = j % 10;}
                        TX2_write2buff((u8)(j%10+'0'));
                        PrintString2("字节内容!\r\n");
                    }
                    else        PrintString2("写入错误!\r\n");
                }
                F0 = 1;
            }
            else if((RX2_Buffer[0] == 'R') && (COM2.RX_Cnt >= 12) && (RX2_Buffer[10] == ' '))   //读出N个字节
            {
                j = GetDataLength();
                if((j > 0) && (j < EE_BUF_LENGTH))
                {
                    SPI_Read_Nbytes(Flash_addr,tmp,j);
                    PrintString2("读出");
                    if(j>=100)  TX2_write2buff((u8)(j/100+'0'));
                    TX2_write2buff((u8)(j%100/10+'0'));
                    TX2_write2buff((u8)(j%10+'0'));
                    PrintString2("个字节内容如下：\r\n");
                    for(i=0; i<j; i++)  TX2_write2buff(tmp[i]);
                    TX2_write2buff(0x0d);
                    TX2_write2buff(0x0a);
                    F0 = 1;
                }
            }
        }
    }
    if(!F0) PrintString2("命令错误!\r\n");
}

/************************************************
检测Flash是否准备就绪
入口参数: 无
出口参数:
    0 : 没有检测到正确的Flash
    1 : Flash准备就绪
************************************************/
void FlashCheckID(void)
{
    SPI_CE_Low();
    SPI_WriteByte(SFC_RDID);        //发送读取ID命令
    SPI_WriteByte(0x00);            //空读3个字节
    SPI_WriteByte(0x00);
    SPI_WriteByte(0x00);
    FLASH_ID1 = SPI_ReadByte();     //读取制造商ID1
    FLASH_ID  = SPI_ReadByte();     //读取设备ID
    FLASH_ID2 = SPI_ReadByte();     //读取制造商ID2
    SPI_CE_High();

//    TX2_write2buff(FLASH_ID1);
//    TX2_write2buff(FLASH_ID);
//    TX2_write2buff(FLASH_ID2);
	
    if((FLASH_ID1 == 0x9d) && (FLASH_ID2 == 0x7f))  B_FlashOK = 1;  //检测是否为PM25LVxx系列的Flash
    else if(FLASH_ID == 0x12)  B_FlashOK = 2;                       //检测是否为W25X4x系列的Flash
    else if(FLASH_ID == 0x13)  B_FlashOK = 3;                       //检测是否为W25X8x系列的Flash
    else if(FLASH_ID == 0x17)  B_FlashOK = 4;                       //检测是否为W25X128系列的Flash
    else                                            B_FlashOK = 0;
}

/************************************************
检测Flash的忙状态
入口参数: 无
出口参数:
    0 : Flash处于空闲状态
    1 : Flash处于忙状态
************************************************/
u8 CheckFlashBusy(void)
{
    u8  dat;

    SPI_CE_Low();
    SPI_WriteByte(SFC_RDSR);        //发送读取状态命令
    dat = SPI_ReadByte();           //读取状态
    SPI_CE_High();

    return (dat);                   //状态值的Bit0即为忙标志
}

/************************************************
使能Flash写命令
入口参数: 无
出口参数: 无
************************************************/
void FlashWriteEnable(void)
{
    while(CheckFlashBusy() > 0);    //Flash忙检测
    SPI_CE_Low();
    SPI_WriteByte(SFC_WREN);        //发送写使能命令
    SPI_CE_High();
}

/************************************************
擦除整片Flash
入口参数: 无
出口参数: 无
************************************************/
/*
void FlashChipErase(void)
{
    if(B_FlashOK)
    {
        FlashWriteEnable();             //使能Flash写命令
        SPI_CE_Low();
        SPI_WriteByte(SFC_CHIPER);      //发送片擦除命令
        SPI_CE_High();
    }
}
*/

/************************************************
擦除扇区, 一个扇区4KB
入口参数: 无
出口参数: 无
************************************************/
void FlashSectorErase(u32 addr)
{
    if(B_FlashOK)
    {
        FlashWriteEnable();             //使能Flash写命令
        SPI_CE_Low();
        if(B_FlashOK == 1)
        {
            SPI_WriteByte(SFC_SECTORER1);    //发送扇区擦除命令
        }
        else
        {
            SPI_WriteByte(SFC_SECTORER2);    //发送扇区擦除命令
        }
        SPI_WriteByte(((u8 *)&addr)[1]);           //设置起始地址
        SPI_WriteByte(((u8 *)&addr)[2]);
        SPI_WriteByte(((u8 *)&addr)[3]);
        SPI_CE_High();
    }
}

/************************************************
从Flash中读取数据
入口参数:
    addr   : 地址参数
    buffer : 缓冲从Flash中读取的数据
    size   : 数据块大小
出口参数:
    无
************************************************/
void SPI_Read_Nbytes(u32 addr, u8 *buffer, u16 size)
{
    if(size == 0)   return;
    if(!B_FlashOK)  return;
    while(CheckFlashBusy() > 0);        //Flash忙检测

    SPI_CE_Low();                       //enable device
    SPI_WriteByte(SFC_READ);            //read command

    SPI_WriteByte(((u8 *)&addr)[1]);    //设置起始地址
    SPI_WriteByte(((u8 *)&addr)[2]);
    SPI_WriteByte(((u8 *)&addr)[3]);

    do{
        *buffer = SPI_ReadByte();       //receive byte and store at buffer
        buffer++;
    }while(--size);                     //read until no_bytes is reached
    SPI_CE_High();                      //disable device
}

/************************************************************************
读出n个字节,跟指定的数据进行比较, 错误返回1,正确返回0
************************************************************************/
u8 SPI_Read_Compare(u32 addr, u8 *buffer, u16 size)
{
    u8  j;
    if(size == 0)   return 2;
    if(!B_FlashOK)  return 2;
    while(CheckFlashBusy() > 0);            //Flash忙检测

    j = 0;
    SPI_CE_Low();                           //enable device
    SPI_WriteByte(SFC_READ);                //read command
    SPI_WriteByte(((u8 *)&addr)[1]);        //设置起始地址
    SPI_WriteByte(((u8 *)&addr)[2]);
    SPI_WriteByte(((u8 *)&addr)[3]);
    do
    {
        if(*buffer != SPI_ReadByte())       //receive byte and store at buffer
        {
            j = 1;
            break;
        }
        buffer++;
    }while(--size);         //read until no_bytes is reached
    SPI_CE_High();          //disable device
    return j;
}


/************************************************
写数据到Flash中
入口参数:
    addr   : 地址参数
    buffer : 缓冲需要写入Flash的数据
    size   : 数据块大小
出口参数: 无
************************************************/
void SPI_Write_Nbytes(u32 addr, u8 *buffer, u8 size)
{
    if(size == 0)   return;
    if(!B_FlashOK)  return;
    while(CheckFlashBusy() > 0);        //Flash忙检测


    FlashWriteEnable();                 //使能Flash写命令

    SPI_CE_Low();                       // enable device
    SPI_WriteByte(SFC_PAGEPROG);        // 发送页编程命令
    SPI_WriteByte(((u8 *)&addr)[1]);    //设置起始地址
    SPI_WriteByte(((u8 *)&addr)[2]);
    SPI_WriteByte(((u8 *)&addr)[3]);
    do{
        SPI_WriteByte(*buffer++);       //连续页内写
        addr++;
        if ((addr & 0xff) == 0) break;
    }while(--size);
    SPI_CE_High();                      // disable device
}
