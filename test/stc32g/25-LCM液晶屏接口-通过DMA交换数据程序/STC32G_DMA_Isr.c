/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include "STC32G_DMA.h"
#include "STC32G_LCM.h"

bit DmaLcmFlag;

//========================================================================
// 函数: DMA_LCM_ISR_Handler
// 描述: DMA LCM 中断函数.
// 参数: none.
// 返回: none.
// 版本: V1.0, 2022-03-23
//========================================================================
void DMA_LCM_ISR_Handler (void) interrupt DMA_LCM_VECTOR
{
	// TODO: 在此处添加用户代码
	if(DMA_LCM_STA & 0x01)
	{
		if(DmaLcmFlag)
		{
			DmaLcmFlag = 0;
			DMA_LCM_CR = 0;
		}
		else
		{
			LCM_Cnt--;
			if(LCM_Cnt == 0)
			{
				DMA_LCM_CR = 0;
				LCD_CS=1;
			}
			else
			{
				DMA_LCM_CR = 0xa0;	//Write dat
			}
		}
		DMA_LCM_STA = 0;		//清标志位
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
	
	//------------- LCM --------------
	if(LCMIFSTA & 0x01)
	{
		LCMIFSTA = 0x00;
		LcmFlag = 0;
	}
	
	//---------- DMA LCM -------------
	if(DMA_LCM_STA & 0x01)
	{
		if(DmaLcmFlag)
		{
			DmaLcmFlag = 0;
			DMA_LCM_CR = 0;
		}
		else
		{
			LCM_Cnt--;
			if(LCM_Cnt == 0)
			{
				DMA_LCM_CR = 0;
				LCD_CS=1;
			}
			else
			{
				DMA_LCM_CR = 0xa0;	//Write dat
			}
		}
		DMA_LCM_STA = 0;		//清标志位
	}
}
