/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"STC32G_Exti.h"

//========================================================================
// 函数: u8	Ext_Inilize(u8 EXT, EXTI_InitTypeDef *INTx)
// 描述: 外部中断初始化程序.
// 参数: EXT: 外部中断号, INTx: 结构参数,请参考Exti.h里的定义.
// 返回: 成功返回 SUCCESS, 错误返回 FAIL.
// 版本: V1.0, 2012-10-22
//========================================================================
u8	Ext_Inilize(u8 EXT, EXTI_InitTypeDef *INTx)
{
	if(EXT >  EXT_INT1)	return FAIL;	//空操作
	
	if(EXT == EXT_INT0)	//外中断0
	{
		IE0  = 0;					//外中断0标志位
		INT0_Mode(INTx->EXTI_Mode);
		return SUCCESS;		//成功
	}

	if(EXT == EXT_INT1)	//外中断1
	{
		IE1  = 0;					//外中断1标志位
		INT1_Mode(INTx->EXTI_Mode);
		return SUCCESS;		//成功
	}
	return FAIL;	//失败
}
