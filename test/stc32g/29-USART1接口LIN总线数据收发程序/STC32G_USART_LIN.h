/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#ifndef __STC32G_USART_LIN_H
#define __STC32G_USART_LIN_H	 

#include	"config.h"

//========================================================================
//                              定义声明
//========================================================================

#define	USART1	1
#define	USART2	2

#define FRAME_LEN       8    //数据长度: 8 字节

#define	LinMasterMode		0
#define	LinSlaveMode		1

//========================================================================
//                              USART设置
//========================================================================


//========================================================================
//                              变量声明
//========================================================================

typedef struct
{ 
	u8	LIN_Enable;				//LIN总线使能  	ENABLE,DISABLE
	u8	LIN_Mode;				//LIN总线模式  	LinMasterMode,LinSlaveMode
	u8	LIN_AutoSync;			//自动同步使能  	ENABLE,DISABLE
	u16	LIN_Baudrate;			//LIN波特率
} USARTx_LIN_InitDefine; 

//========================================================================
//                              外部声明
//========================================================================

u8 UASRT_LIN_Configuration(u8 USARTx, USARTx_LIN_InitDefine *USART);
void UsartLinSendChecksum(u8 USARTx, u8 *dat, u8 len);
void UsartLinSendData(u8 USARTx, u8 *pdat, u8 len);
void UsartLinSendFrame(u8 USARTx, u8 lid, u8 *pdat, u8 len);
void UsartLinSendHeader(u8 USARTx, u8 lid);

#endif

