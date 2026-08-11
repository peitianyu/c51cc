/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include "STC32G_DMA.h"
#include "STC32G_SPI.h"

bit	DmaTx1Flag;
bit	DmaRx1Flag;
bit	DmaTx2Flag;
bit	DmaRx2Flag;
bit	DmaTx3Flag;
bit	DmaRx3Flag;
bit	DmaTx4Flag;
bit	DmaRx4Flag;

bit DmaM2MFlag = 0;

bit	SpiTxFlag;
bit	SpiRxFlag;

bit	u2sFlag;    //UART to SPI
bit	s2uFlag;    //SPI to UART

bit	SpiSendFlag;
bit	UartSendFlag;

//========================================================================
// 函数: DMA_M2M_ISR_Handler
// 描述: DMA M2M 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_M2M_ISR_Handler (void) interrupt DMA_M2M_VECTOR
{
	// TODO: 在此处添加用户代码
	if(DMA_M2M_STA & 0x01)	//M2M传输完成
	{
		DMA_M2M_STA &= ~0x01;	//清标志位
		DmaM2MFlag = 1;
		if(u2sFlag)
		{
			u2sFlag = 0;
			SpiSendFlag = 1;
		}
		if(s2uFlag)
		{
			s2uFlag = 0;
			UartSendFlag = 1;
		}
	}
}

//========================================================================
// 函数: DMA_UART1TX_ISR_Handler
// 描述: DMA UART1 TX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART1TX_ISR_Handler (void) interrupt DMA_UR1T_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR1T_STA & 0x01)	//发送完成
	{
		DMA_UR1T_STA &= ~0x01;	//清标志位
		DmaTx1Flag = 1;
	}
	if (DMA_UR1T_STA & 0x04)	//数据覆盖
	{
		DMA_UR1T_STA &= ~0x04;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART1RX_ISR_Handler
// 描述: DMA UART1 RX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART1RX_ISR_Handler (void) interrupt DMA_UR1R_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR1R_STA & 0x01)	//接收完成
	{
		DMA_UR1R_STA &= ~0x01;	//清标志位
		DmaRx1Flag = 1;
	}
	if (DMA_UR1R_STA & 0x02)	//数据丢弃
	{
		DMA_UR1R_STA &= ~0x02;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART2TX_ISR_Handler
// 描述: DMA UART2 TX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART2TX_ISR_Handler (void) interrupt DMA_UR2T_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR2T_STA & 0x01)	//发送完成
	{
		DMA_UR2T_STA &= ~0x01;	//清标志位
		DmaTx2Flag = 1;
	}
	if (DMA_UR2T_STA & 0x04)	//数据覆盖
	{
		DMA_UR2T_STA &= ~0x04;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART2RX_ISR_Handler
// 描述: DMA UART2 RX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART2RX_ISR_Handler (void) interrupt DMA_UR2R_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR2R_STA & 0x01)	//接收完成
	{
		DMA_UR2R_STA &= ~0x01;	//清标志位
		DmaRx2Flag = 1;
	}
	if (DMA_UR2R_STA & 0x02)	//数据丢弃
	{
		DMA_UR2R_STA &= ~0x02;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART3TX_ISR_Handler
// 描述: DMA UART3 TX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART3TX_ISR_Handler (void) interrupt DMA_UR3T_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR3T_STA & 0x01)	//发送完成
	{
		DMA_UR3T_STA &= ~0x01;	//清标志位
		DmaTx3Flag = 1;
	}
	if (DMA_UR3T_STA & 0x04)	//数据覆盖
	{
		DMA_UR3T_STA &= ~0x04;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART3RX_ISR_Handler
// 描述: DMA UART3 RX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART3RX_ISR_Handler (void) interrupt DMA_UR3R_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR3R_STA & 0x01)	//接收完成
	{
		DMA_UR3R_STA &= ~0x01;	//清标志位
		DmaRx3Flag = 1;
	}
	if (DMA_UR3R_STA & 0x02)	//数据丢弃
	{
		DMA_UR3R_STA &= ~0x02;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART4TX_ISR_Handler
// 描述: DMA UART4 TX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART4TX_ISR_Handler (void) interrupt DMA_UR4T_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR4T_STA & 0x01)	//发送完成
	{
		DMA_UR4T_STA &= ~0x01;	//清标志位
		DmaTx4Flag = 1;
	}
	if (DMA_UR4T_STA & 0x04)	//数据覆盖
	{
		DMA_UR4T_STA &= ~0x04;	//清标志位
	}
}

//========================================================================
// 函数: DMA_UART4RX_ISR_Handler
// 描述: DMA UART4 RX 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_UART4RX_ISR_Handler (void) interrupt DMA_UR4R_VECTOR
{
	// TODO: 在此处添加用户代码
	if (DMA_UR4R_STA & 0x01)	//接收完成
	{
		DMA_UR4R_STA &= ~0x01;	//清标志位
		DmaRx4Flag = 1;
	}
	if (DMA_UR4R_STA & 0x02)	//数据丢弃
	{
		DMA_UR4R_STA &= ~0x02;	//清标志位
	}
}

//========================================================================
// 函数: DMA_SPI_ISR_Handler
// 描述: DMA SPI 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_SPI_ISR_Handler (void) interrupt DMA_SPI_VECTOR
{
	// TODO: 在此处添加用户代码
	if(DMA_SPI_STA & 0x01)	//通信完成
	{
		DMA_SPI_STA &= ~0x01;	//清标志位
		if(SPCTL & 0x10) 
		{ //主机模式
			SpiTxFlag = 1;
			SPI_SS_2 = 1;
		}
		else 
		{ //从机模式
			SpiRxFlag = 1;
		}
	}
	if(DMA_SPI_STA & 0x02)	//数据丢弃
	{
		DMA_SPI_STA &= ~0x02;	//清标志位
	}
	if(DMA_SPI_STA & 0x04)	//数据覆盖
	{
		DMA_SPI_STA &= ~0x04;	//清标志位
	}
}

//========================================================================
// 函数: DMA_ISR_Handler
// 描述: DMA中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2021-05-25
//========================================================================
void DMA_ISR_Handler (void) interrupt 13
{
	// TODO: 在此处添加用户代码
	
	//----------- DMA M2M --------------
	if(DMA_M2M_STA & 0x01)	//M2M传输完成
	{
		DMA_M2M_STA &= ~0x01;	//清标志位
		DmaM2MFlag = 1;
		if(u2sFlag)
		{
			u2sFlag = 0;
			SpiSendFlag = 1;
		}
		if(s2uFlag)
		{
			s2uFlag = 0;
			UartSendFlag = 1;
		}
	}

	//---------- DMA UART1 -------------
	if (DMA_UR1T_STA & 0x01)	//发送完成
	{
		DMA_UR1T_STA &= ~0x01;	//清标志位
		DmaTx1Flag = 1;
	}
	if (DMA_UR1T_STA & 0x04)	//数据覆盖
	{
		DMA_UR1T_STA &= ~0x04;	//清标志位
	}
	
	if (DMA_UR1R_STA & 0x01)	//接收完成
	{
		DMA_UR1R_STA &= ~0x01;	//清标志位
		DmaRx1Flag = 1;
	}
	if (DMA_UR1R_STA & 0x02)	//数据丢弃
	{
		DMA_UR1R_STA &= ~0x02;	//清标志位
	}
	//---------- DMA UART2 -------------
	if (DMA_UR2T_STA & 0x01)	//发送完成
	{
		DMA_UR2T_STA &= ~0x01;	//清标志位
		DmaTx2Flag = 1;
	}
	if (DMA_UR2T_STA & 0x04)	//数据覆盖
	{
		DMA_UR2T_STA &= ~0x04;	//清标志位
	}
	
	if (DMA_UR2R_STA & 0x01)	//接收完成
	{
		DMA_UR2R_STA &= ~0x01;	//清标志位
		DmaRx2Flag = 1;
	}
	if (DMA_UR2R_STA & 0x02)	//数据丢弃
	{
		DMA_UR2R_STA &= ~0x02;	//清标志位
	}
	//---------- DMA UART3 -------------
	if (DMA_UR3T_STA & 0x01)	//发送完成
	{
		DMA_UR3T_STA &= ~0x01;	//清标志位
		DmaTx3Flag = 1;
	}
	if (DMA_UR3T_STA & 0x04)	//数据覆盖
	{
		DMA_UR3T_STA &= ~0x04;	//清标志位
	}
	
	if (DMA_UR3R_STA & 0x01)	//接收完成
	{
		DMA_UR3R_STA &= ~0x01;	//清标志位
		DmaRx3Flag = 1;
	}
	if (DMA_UR3R_STA & 0x02)	//数据丢弃
	{
		DMA_UR3R_STA &= ~0x02;	//清标志位
	}
	//---------- DMA UART4 -------------
	if (DMA_UR4T_STA & 0x01)	//发送完成
	{
		DMA_UR4T_STA &= ~0x01;	//清标志位
		DmaTx4Flag = 1;
	}
	if (DMA_UR4T_STA & 0x04)	//数据覆盖
	{
		DMA_UR4T_STA &= ~0x04;	//清标志位
	}
	
	if (DMA_UR4R_STA & 0x01)	//接收完成
	{
		DMA_UR4R_STA &= ~0x01;	//清标志位
		DmaRx4Flag = 1;
	}
	if (DMA_UR4R_STA & 0x02)	//数据丢弃
	{
		DMA_UR4R_STA &= ~0x02;	//清标志位
	}

	//---------- DMA SPI -------------
	if(DMA_SPI_STA & 0x01)	//通信完成
	{
		DMA_SPI_STA &= ~0x01;	//清标志位
		if(SPCTL & 0x10) 
		{ //主机模式
			SpiTxFlag = 1;
			SPI_SS_2 = 1;
		}
		else 
		{ //从机模式
			SpiRxFlag = 1;
		}
	}
	if(DMA_SPI_STA & 0x02)	//数据丢弃
	{
		DMA_SPI_STA &= ~0x02;	//清标志位
	}
	if(DMA_SPI_STA & 0x04)	//数据覆盖
	{
		DMA_SPI_STA &= ~0x04;	//清标志位
	}
}
