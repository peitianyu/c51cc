/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#ifndef	__STC32G_EXTI_H
#define	__STC32G_EXTI_H

#include	"config.h"

//========================================================================
//                             外部中断设置
//========================================================================

#define 	INT0_Mode(n)		(n==0?(IT0 = 0):(IT0 = 1))	/* INT0中断模式  下降沿/上升,下降沿中断 */
#define 	INT1_Mode(n)		(n==0?(IT1 = 0):(IT1 = 1))	/* INT0中断模式  下降沿/上升,下降沿中断 */

//========================================================================
//                              定义声明
//========================================================================

#define	EXT_INT0			0	//外中断0
#define	EXT_INT1			1	//外中断1
#define	EXT_INT2			2	//外中断2
#define	EXT_INT3			3	//外中断3
#define	EXT_INT4			4	//外中断4

#define	EXT_MODE_RiseFall	0	//上升沿/下降沿中断
#define	EXT_MODE_Fall			1	//下降沿中断

typedef struct
{
	u8	EXTI_Mode;			//中断模式,  	EXT_MODE_RiseFall, EXT_MODE_Fall
} EXTI_InitTypeDef;

extern u8 WakeUpSource;

u8	Ext_Inilize(u8 EXT, EXTI_InitTypeDef *INTx);

#endif
