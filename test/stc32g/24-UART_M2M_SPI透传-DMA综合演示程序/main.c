/*---------------------------------------------------------------------*/
/* --- STC MCU Limited ------------------------------------------------*/
/* --- STC 1T Series MCU Demo Programme -------------------------------*/
/* --- Mobile: (86)13922805190 ----------------------------------------*/
/* --- Fax: 86-0513-55012956,55012947,55012969 ------------------------*/
/* --- Tel: 86-0513-55012928,55012929,55012966 ------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/* --- Web: www.STCMCUDATA.com  ---------------------------------------*/
/* --- BBS: www.STCAIMCU.com  -----------------------------------------*/
/* --- QQ:  800003751 -------------------------------------------------*/
/* 如果要在程序中使用此代码,请在程序中注明使用了STC的资料及程序            */
/*---------------------------------------------------------------------*/

#include	"config.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_SPI.h"
#include	"STC32G_UART.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_DMA.h"
#include	"STC32G_Switch.h"

/*************   功能说明   ***************

UART_DMA, M2M_DMA, SPI_DMA 综合使用演示例程.

通过串口发送数据给MCU1，MCU1将接收到的数据由SPI发送给MCU2，MCU2再通过串口发送出去.

通过串口发送数据给MCU2，MCU2将接收到的数据由SPI发送给MCU1，MCU1再通过串口发送出去.

MCU1/MCU2: UART接收 -> UART Rx DMA -> M2M -> SPI Tx DMA -> SPI发送

MCU2/MCU1: SPI接收 -> SPI Rx DMA -> M2M -> UART Tx DMA -> UART发送

         MCU1                          MCU2
  |-----------------|           |-----------------|
  |            MISO |-----------| MISO            |
--| TX         MOSI |-----------| MOSI         TX |--
  |            SCLK |-----------| SCLK            |
--| RX           SS |-----------| SS           RX |--
  |-----------------|           |-----------------|


下载时, 选择时钟 22.1184MHz (可以在配置文件"config.h"中修改).

******************************************/

/*************	本地常量声明	**************/

#define BUF_LENGTH          107			//n+1

/*************	本地变量声明	**************/

u8 xdata UartTxBuffer[256];
u8 xdata UartRxBuffer[256];
u8 xdata SpiTxBuffer[256];
u8 xdata SpiRxBuffer[256];

/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/


/******************** IO口配置 ********************/
void	GPIO_config(void)
{
	P2_MODE_IO_PU(GPIO_Pin_All);		//P2 设置为准双向口
	P4_MODE_IO_PU(GPIO_Pin_6 | GPIO_Pin_7);		//P4.6,P4.7 设置为准双向口

	UART2_SW(UART2_SW_P46_P47);		//UART2_SW_P10_P11,UART2_SW_P46_P47
	SPI_SW(SPI_P22_P23_P24_P25);	//SPI_P54_P13_P14_P15,SPI_P22_P23_P24_P25,SPI_P54_P40_P41_P43,SPI_P35_P34_P33_P32
	SPI_SS_2 = 1;
}

/******************** UART配置 ********************/
void	UART_config(void)
{
	COMx_InitDefine		COMx_InitStructure;		//结构定义

	COMx_InitStructure.UART_Mode      = UART_8bit_BRTx;	//模式,   UART_ShiftRight,UART_8bit_BRTx,UART_9bit,UART_9bit_BRTx
//	COMx_InitStructure.UART_BRT_Use   = BRT_Timer2;		//选择波特率发生器, BRT_Timer2 (注意: 串口2固定使用BRT_Timer2, 所以不用选择)
	COMx_InitStructure.UART_BaudRate  = 115200ul;		//波特率,     110 ~ 115200
	COMx_InitStructure.UART_RxEnable  = ENABLE;			//接收允许,   ENABLE 或 DISABLE
	UART_Configuration(UART2, &COMx_InitStructure);		//初始化串口2 UART1,UART2,UART3,UART4
	NVIC_UART2_Init(ENABLE,Priority_1);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

/******************** SPI 配置 ********************/
void	SPI_config(void)
{
	SPI_InitTypeDef		SPI_InitStructure;

	SPI_InitStructure.SPI_Enable    = ENABLE;			//SPI启动    ENABLE, DISABLE
	SPI_InitStructure.SPI_SSIG      = DISABLE;			//片选位     ENABLE(忽略SS引脚功能), DISABLE(SS确定主机从机)
	SPI_InitStructure.SPI_FirstBit  = SPI_MSB;			//移位方向   SPI_MSB, SPI_LSB
	SPI_InitStructure.SPI_Mode      = SPI_Mode_Slave;	//主从选择   SPI_Mode_Master, SPI_Mode_Slave
	SPI_InitStructure.SPI_CPOL      = SPI_CPOL_Low;		//时钟相位   SPI_CPOL_High,   SPI_CPOL_Low
	SPI_InitStructure.SPI_CPHA      = SPI_CPHA_1Edge;	//数据边沿   SPI_CPHA_1Edge,  SPI_CPHA_2Edge
	SPI_InitStructure.SPI_Speed     = SPI_Speed_16;		//SPI速度    SPI_Speed_4, SPI_Speed_8, SPI_Speed_16, SPI_Speed_2
	SPI_Init(&SPI_InitStructure);
	NVIC_SPI_Init(DISABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

/******************** DMA 配置 ********************/
void	DMA_config(void)
{
	DMA_M2M_InitTypeDef		DMA_M2M_InitStructure;		//结构定义
	DMA_SPI_InitTypeDef		DMA_SPI_InitStructure;		//结构定义
	DMA_UART_InitTypeDef	DMA_UART_InitStructure;		//结构定义

	//----------------------------------------------
	DMA_UART_InitStructure.DMA_TX_Length = BUF_LENGTH;	//DMA传输总字节数  	(0~65535) + 1
	DMA_UART_InitStructure.DMA_TX_Buffer = (u16)UartTxBuffer;	//发送数据存储地址
	DMA_UART_InitStructure.DMA_RX_Length = BUF_LENGTH;	//DMA传输总字节数  	(0~65535) + 1
	DMA_UART_InitStructure.DMA_RX_Buffer = (u16)UartRxBuffer;	//接收数据存储地址
	DMA_UART_InitStructure.DMA_TX_Enable = ENABLE;		//DMA使能  	ENABLE,DISABLE
	DMA_UART_InitStructure.DMA_RX_Enable = ENABLE;		//DMA使能  	ENABLE,DISABLE
	DMA_UART_Inilize(UART2, &DMA_UART_InitStructure);	//初始化

	NVIC_DMA_UART2_Tx_Init(ENABLE,Priority_0,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0~Priority_3; 总线优先级(低到高) Priority_0~Priority_3
	NVIC_DMA_UART2_Rx_Init(ENABLE,Priority_0,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0~Priority_3; 总线优先级(低到高) Priority_0~Priority_3
	DMA_UR2R_CLRFIFO();		//清空 DMA FIFO
	DMA_UR2R_TRIG();	//触发UART接收功能

	//----------------------------------------------
	DMA_M2M_InitStructure.DMA_Enable = ENABLE;			//DMA使能  	ENABLE,DISABLE
	DMA_M2M_InitStructure.DMA_Length = BUF_LENGTH;			//DMA传输总字节数  	(0~65535) + 1
	DMA_M2M_InitStructure.DMA_Tx_Buffer = (u16)UartRxBuffer;	//发送数据存储地址
	DMA_M2M_InitStructure.DMA_Rx_Buffer = (u16)SpiTxBuffer;	//接收数据存储地址
	DMA_M2M_InitStructure.DMA_SRC_Dir = M2M_ADDR_INC;		//数据源地址改变方向  	M2M_ADDR_INC,M2M_ADDR_DEC
	DMA_M2M_InitStructure.DMA_DEST_Dir = M2M_ADDR_INC;	//数据目标地址改变方向 	M2M_ADDR_INC,M2M_ADDR_DEC
	DMA_M2M_Inilize(&DMA_M2M_InitStructure);		//初始化
	NVIC_DMA_M2M_Init(ENABLE,Priority_0,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0~Priority_3; 总线优先级(低到高) Priority_0~Priority_3

	//----------------------------------------------
	DMA_SPI_InitStructure.DMA_Enable = DISABLE;					//DMA使能  	ENABLE,DISABLE
	DMA_SPI_InitStructure.DMA_Tx_Enable = ENABLE;				//DMA发送数据使能  	ENABLE,DISABLE
	DMA_SPI_InitStructure.DMA_Rx_Enable = ENABLE;				//DMA接收数据使能  	ENABLE,DISABLE
	DMA_SPI_InitStructure.DMA_Length = BUF_LENGTH;			//DMA传输总字节数  	(0~65535) + 1
	DMA_SPI_InitStructure.DMA_Tx_Buffer = (u16)SpiTxBuffer;	//发送数据存储地址
	DMA_SPI_InitStructure.DMA_Rx_Buffer = (u16)SpiRxBuffer;	//接收数据存储地址
	DMA_SPI_InitStructure.DMA_SS_Sel = SPI_SS_P22;			//自动控制SS脚选择 	SPI_SS_P12,SPI_SS_P22,SPI_SS_P74,SPI_SS_P35
	DMA_SPI_InitStructure.DMA_AUTO_SS = DISABLE;				//自动控制SS脚使能  	ENABLE,DISABLE
	DMA_SPI_Inilize(&DMA_SPI_InitStructure);		//初始化
	SET_DMA_SPI_CR(DMA_ENABLE | SPI_TRIG_S | CLR_FIFO);	//bit7 1:使能 SPI_DMA, bit5 1:开始 SPI_DMA 从机模式, bit0 1:清除 SPI_DMA FIFO
	NVIC_DMA_SPI_Init(ENABLE,Priority_0,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0~Priority_3; 总线优先级(低到高) Priority_0~Priority_3
}

void M2M_UART_SPI(u16 txbuf, u16 rxbuf)
{
	DMA_M2M_CLR_STA();
	SET_M2M_TX_FIFO(txbuf);
	SET_M2M_RX_FIFO(rxbuf);
	DMA_M2M_TRIG();
}

void M2M_SPI_UART(u16 txbuf, u16 rxbuf)
{
	DMA_M2M_CLR_STA();
	SET_M2M_TX_FIFO(txbuf);
	SET_M2M_RX_FIFO(rxbuf);
	DMA_M2M_TRIG();
}

void UART_DMA_Tx(void)
{
	DMA_UR2T_TRIG();
}

void UART_DMA_Rx(void)
{
	DMA_UR2R_TRIG();
}

void SPI_DMA_Master(void)
{
	SET_DMA_SPI_CR(0);
	_nop_();
	_nop_();
	_nop_();
	_nop_();
	_nop_();
	_nop_();
	SPI_SS_2 = 0;
	SPCTL = 0xd2;   //使能 SPI 主机模式，忽略SS引脚功能
	SET_DMA_SPI_CR(DMA_ENABLE | SPI_TRIG_M);	//bit7 1:使能 SPI_DMA, bit6 1:开始 SPI_DMA 主机模式
}

void SPI_DMA_Slave(void)
{
	SET_DMA_SPI_CR(0);
	_nop_();
	_nop_();
	_nop_();
	_nop_();
	_nop_();
	_nop_();
	SPCTL = 0x42;  //重新设置为从机待机
	SET_DMA_SPI_CR(DMA_ENABLE | SPI_TRIG_S);	//bit7 1:使能 SPI_DMA, bit5 1:开始 SPI_DMA 从机模式
}

/******************** task A **************************/
void main(void)
{
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	UART_config();
	SPI_config();
	DMA_config();
	EA = 1;

	printf("STC32G UART-DMA-SPI互为主从透传程序.\r\n");
	
	while (1)
	{
		//UART接收 -> UART DMA -> SPI DMA -> SPI发送
		if(DmaRx2Flag)
		{
			DmaRx2Flag = 0;
			u2sFlag = 1;
			M2M_UART_SPI((u16)UartRxBuffer,(u16)SpiTxBuffer);			//UART Memory -> SPI Memory
		}

		if(SpiSendFlag)
		{
			SpiSendFlag = 0;
			UART_DMA_Rx();			//UART Recive Continue
			SPI_DMA_Master();		//SPI Send Memory
		}

		if(SpiTxFlag)
		{
			SpiTxFlag = 0;
			SPI_DMA_Slave();		//SPI Slave Mode
		}

		
		//SPI接收 -> SPI DMA -> UART DMA -> UART发送
		if(SpiRxFlag)
		{
			SpiRxFlag = 0;
			s2uFlag = 1;
			M2M_SPI_UART((u16)SpiRxBuffer, (u16)UartTxBuffer);			//SPI Memory -> UART Memory
		}

		if(UartSendFlag)
		{
			UartSendFlag = 0;
			SPI_DMA_Slave();		//SPI Slave Mode
			UART_DMA_Tx();			//UART Send Memory
		}
	}
}



