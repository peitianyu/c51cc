/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/
/* 此头文件的IO口初始化库函数由热心用户LAOXU提供，有兴趣的用户可参考使用   */
/* 例程来源：https://www.stcaimcu.com/forum.php?mod=viewthread&tid=818 */
/*---------------------------------------------------------------------*/

#ifndef	__STC_GPIO_H
#define	__STC_GPIO_H

//========================================================================
//                              定义声明
//========================================================================

#define	GPIO_PullUp		0L	//上拉准双向口
#define	GPIO_OUT_PP		1L	//推挽输出
#define	GPIO_HighZ		2L	//浮空输入
#define	GPIO_OUT_OD		3L	//开漏输出

#define	GPIO_Pin_0		0x01	//IO引脚 Px.0
#define	GPIO_Pin_1		0x02	//IO引脚 Px.1
#define	GPIO_Pin_2		0x04	//IO引脚 Px.2
#define	GPIO_Pin_3		0x08	//IO引脚 Px.3
#define	GPIO_Pin_4		0x10	//IO引脚 Px.4
#define	GPIO_Pin_5		0x20	//IO引脚 Px.5
#define	GPIO_Pin_6		0x40	//IO引脚 Px.6
#define	GPIO_Pin_7		0x80	//IO引脚 Px.7
#define	GPIO_Pin_LOW	0x0F	//IO低4位引脚
#define	GPIO_Pin_HIGH	0xF0	//IO高4位引脚
#define	GPIO_Pin_All	0xFF	//IO所有引脚

#define	GPIO_P0			0		//
#define	GPIO_P1			1
#define	GPIO_P2			2
#define	GPIO_P3			3
#define	GPIO_P4			4
#define	GPIO_P5			5
#define	GPIO_P6			6
#define	GPIO_P7			7

#define	GPIO_PullUp_0		(((GPIO_PullUp<<16) | (GPIO_PullUp<<7) | GPIO_Pin_0) & 0x010101L)	  //IO引脚 Px.0, 上拉准双向口
#define	GPIO_OUT_PP_0		(((GPIO_OUT_PP<<16) | (GPIO_OUT_PP<<7) | GPIO_Pin_0) & 0x010101L)	  //             推挽输出
#define	GPIO_HighZ_0		(((GPIO_HighZ <<16) | (GPIO_HighZ <<7) | GPIO_Pin_0) & 0x010101L)	  //             浮空输入
#define	GPIO_OUT_OD_0		(((GPIO_OUT_OD<<16) | (GPIO_OUT_OD<<7) | GPIO_Pin_0) & 0x010101L)	  //             开漏输出
#define	GPIO_PullUp_1		(((GPIO_PullUp<<17) | (GPIO_PullUp<<8) | GPIO_Pin_1) & 0x020202L)	  //IO引脚 Px.1, 上拉准双向口
#define	GPIO_OUT_PP_1		(((GPIO_OUT_PP<<17) | (GPIO_OUT_PP<<8) | GPIO_Pin_1) & 0x020202L)	  //             推挽输出
#define	GPIO_HighZ_1		(((GPIO_HighZ <<17) | (GPIO_HighZ <<8) | GPIO_Pin_1) & 0x020202L)	  //             浮空输入
#define	GPIO_OUT_OD_1		(((GPIO_OUT_OD<<17) | (GPIO_OUT_OD<<8) | GPIO_Pin_1) & 0x020202L)	  //             开漏输出
#define	GPIO_PullUp_2		(((GPIO_PullUp<<18) | (GPIO_PullUp<<9) | GPIO_Pin_2) & 0x040404L)	  //IO引脚 Px.2, 上拉准双向口
#define	GPIO_OUT_PP_2		(((GPIO_OUT_PP<<18) | (GPIO_OUT_PP<<9) | GPIO_Pin_2) & 0x040404L)	  //             推挽输出
#define	GPIO_HighZ_2		(((GPIO_HighZ <<18) | (GPIO_HighZ <<9) | GPIO_Pin_2) & 0x040404L)	  //             浮空输入
#define	GPIO_OUT_OD_2		(((GPIO_OUT_OD<<18) | (GPIO_OUT_OD<<9) | GPIO_Pin_2) & 0x040404L)	  //             开漏输出
#define	GPIO_PullUp_3		(((GPIO_PullUp<<19) | (GPIO_PullUp<<10)| GPIO_Pin_3) & 0x080808L)	  //IO引脚 Px.3, 上拉准双向口
#define	GPIO_OUT_PP_3		(((GPIO_OUT_PP<<19) | (GPIO_OUT_PP<<10)| GPIO_Pin_3) & 0x080808L)	  //             推挽输出
#define	GPIO_HighZ_3		(((GPIO_HighZ <<19) | (GPIO_HighZ <<10)| GPIO_Pin_3) & 0x080808L)	  //             浮空输入
#define	GPIO_OUT_OD_3		(((GPIO_OUT_OD<<19) | (GPIO_OUT_OD<<10)| GPIO_Pin_3) & 0x080808L)	  //             开漏输出
#define	GPIO_PullUp_4		(((GPIO_PullUp<<20) | (GPIO_PullUp<<11)| GPIO_Pin_4) & 0x101010L)	  //IO引脚 Px.4, 上拉准双向口
#define	GPIO_OUT_PP_4		(((GPIO_OUT_PP<<20) | (GPIO_OUT_PP<<11)| GPIO_Pin_4) & 0x101010L)	  //             推挽输出
#define	GPIO_HighZ_4		(((GPIO_HighZ <<20) | (GPIO_HighZ <<11)| GPIO_Pin_4) & 0x101010L)	  //             浮空输入
#define	GPIO_OUT_OD_4		(((GPIO_OUT_OD<<20) | (GPIO_OUT_OD<<11)| GPIO_Pin_4) & 0x101010L)	  //             开漏输出
#define	GPIO_PullUp_5		(((GPIO_PullUp<<21) | (GPIO_PullUp<<12)| GPIO_Pin_5) & 0x202020L)	  //IO引脚 Px.5, 上拉准双向口
#define	GPIO_OUT_PP_5		(((GPIO_OUT_PP<<21) | (GPIO_OUT_PP<<12)| GPIO_Pin_5) & 0x202020L)	  //             推挽输出
#define	GPIO_HighZ_5		(((GPIO_HighZ <<21) | (GPIO_HighZ <<12)| GPIO_Pin_5) & 0x202020L)	  //             浮空输入
#define	GPIO_OUT_OD_5		(((GPIO_OUT_OD<<21) | (GPIO_OUT_OD<<12)| GPIO_Pin_5) & 0x202020L)	  //             开漏输出
#define	GPIO_PullUp_6		(((GPIO_PullUp<<22) | (GPIO_PullUp<<13)| GPIO_Pin_6) & 0x404040L)	  //IO引脚 Px.6, 上拉准双向口
#define	GPIO_OUT_PP_6		(((GPIO_OUT_PP<<22) | (GPIO_OUT_PP<<13)| GPIO_Pin_6) & 0x404040L)	  //             推挽输出
#define	GPIO_HighZ_6		(((GPIO_HighZ <<22) | (GPIO_HighZ <<13)| GPIO_Pin_6) & 0x404040L)	  //             浮空输入
#define	GPIO_OUT_OD_6		(((GPIO_OUT_OD<<22) | (GPIO_OUT_OD<<13)| GPIO_Pin_6) & 0x404040L)	  //             开漏输出
#define	GPIO_PullUp_7		(((GPIO_PullUp<<23) | (GPIO_PullUp<<14)| GPIO_Pin_7) & 0x808080L)	  //IO引脚 Px.7, 上拉准双向口
#define	GPIO_OUT_PP_7		(((GPIO_OUT_PP<<23) | (GPIO_OUT_PP<<14)| GPIO_Pin_7) & 0x808080L)	  //             推挽输出
#define	GPIO_HighZ_7		(((GPIO_HighZ <<23) | (GPIO_HighZ <<14)| GPIO_Pin_7) & 0x808080L)	  //             浮空输入
#define	GPIO_OUT_OD_7		(((GPIO_OUT_OD<<23) | (GPIO_OUT_OD<<14)| GPIO_Pin_7) & 0x808080L)	  //             开漏输出

sfr16   P0Mode  = 0x93;	//  P0M1.n,P0M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P1Mode  = 0x91;	//  P1M1.n,P1M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P2Mode  = 0x95;	//  P2M1.n,P2M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P3Mode  = 0xb1;	//  P3M1.n,P3M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P4Mode  = 0xb3;	//  P4M1.n,P4M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P5Mode  = 0xc9;	//	P5M1.n,P5M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P6Mode  = 0xcb;	//	P6M1.n,P6M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出
sfr16   P7Mode  = 0xe1;	//	P7M1.n,P7M0.n 	=00--->上拉准双向口,  01--->推挽输出
                     	//					=10--->浮空输入,	  11--->开漏输出

			
/*------------------------------------------------------------------------------------
 
			    ===========编 程 实 例===========

                               ------Cortex-M051风格1------

1.void GPIO_SET_MODE(Pn, b7,b6,b5,b4,b3,b2,b1,b0);          // 设置IO口输入输出模式(n=0-7)    

  使用方式：
  GPIO_SET_MODE(P3, PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD);
                 // 设置P3口的bit.7-bit.0位，依次为PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD模式 


2.void GPIO_SET_PIN_MODE(Port, Pin_Mode);                 // 设置IO口其中1位或数位输入输出模式(N=0-7,i=0-7)  

  例如：
  GPIO_SET_PIN_MODE(P3, OUT_OD_Pin6);        // 设置P3口的第bit.6位为OUT_OD模式

  GPIO_SET_PIN_MODE(P2, PullUp_Pin5 | OUT_PP_Pin2 | HighZ_Pin0);        // 设置P2口的第bit.5位为PullUp模式,第bit.2位为OUT_PP模式,第bit.0位为HighZ模式 
--------------------------------------------------------------------------------------*/

#define	GPIO_SET_MODE(Port, b7,b6,b5,b4,b3,b2,b1,b0)   	 Port##_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   

#define	GPIO_SET_PIN_MODE(Port, Pin_Mode)	               Port##_SET_PIN_MODE(Pin_Mode) 	

/*------------------------------------------------------------------------------------

                              ------Cortex-M051风格2------

3.void Pn_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0);          // 设置Pn IO口输入输出模式(n=0-4)    

  使用方式：
  P3_SET_MODE(PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD);
                 // 设置P3口的bit.7-bit.0位，依次为PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD模式 


4.void Pn_SET_PIN_MODE(Pin_Mode);                 // 设置Pn IO口其中1位或数位输入输出模式(N=0-7,i=0-7)  

  例如：
  P3_SET_PIN_MODE(OUT_OD_Pin6);        // 设置P3口的第bit.6位为OUT_OD模式

  P2_SET_PIN_MODE(PullUp_Pin5 | OUT_PP_Pin2 | HighZ_Pin0);        // 设置P2口的第bit.5位为PullUp模式,第bit.2位为OUT_PP模式,第bit.0位为HighZ模式 
--------------------------------------------------------------------------------------*/

#ifndef    __C251__ 
#define	P0_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P0Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P1_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P1Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P2_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P2Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P3_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P3Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P4_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P4Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P5_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P5Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P6_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P6Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  
#define	P7_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P7Mode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);}while(0)  

#define  P0_SET_PIN_MODE(Pin_Mode)	do{P0Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P0Mode |= ((Pin_Mode)>>8); }while(0)  
#define  P1_SET_PIN_MODE(Pin_Mode)	do{P1Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P1Mode |= ((Pin_Mode)>>8); }while(0)  	
#define  P2_SET_PIN_MODE(Pin_Mode)	do{P2Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P2Mode |= ((Pin_Mode)>>8); }while(0)		
#define  P3_SET_PIN_MODE(Pin_Mode)	do{P3Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P3Mode |= ((Pin_Mode)>>8); }while(0) 	
#define  P4_SET_PIN_MODE(Pin_Mode)	do{P4Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P4Mode |= ((Pin_Mode)>>8); }while(0) 	
#define  P5_SET_PIN_MODE(Pin_Mode)	do{P5Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P5Mode |= ((Pin_Mode)>>8); }while(0)  	
#define  P6_SET_PIN_MODE(Pin_Mode)	do{P6Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P6Mode |= ((Pin_Mode)>>8); }while(0) 	
#define  P7_SET_PIN_MODE(Pin_Mode)	do{P7Mode &= ~(((Pin_Mode)<<8) |(Pin_Mode)&0xff); P7Mode |= ((Pin_Mode)>>8); }while(0)  
#endif

#ifndef    __C51__ 
#define	P0_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P0M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
												   P0M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P1_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P1M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
												   P1M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P2_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P2M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
												   P2M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P3_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P3M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
												   P3M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P4_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P4M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
												   P4M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P5_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P5M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
											       P5M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P6_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P6M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
												   P6M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  
#define	P7_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0)   	do{P7M1 = ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01);   \
											       P7M0 = ((b7<<7)&0x80)|((b6<<6)&0x40)|((b5<<5)&0x20)|((b4<<4)&0x10)|((b3<<3)&0x08)|((b2<<2)&0x04)|((b1<<1)&0x02)|(b0&0x01);}while(0)  

#define  P0_MODE1(Mode,Pin)	do{P0M1 &= ~(Pin); P0M0 &= ~(Pin); P0M1 |= (Mode); P0M0 |= (Mode>>8);}while(0) 
#define  P1_MODE1(Mode,Pin)	do{P1M1 &= ~(Pin); P1M0 &= ~(Pin); P1M1 |= (Mode); P1M0 |= (Mode>>8);}while(0) 
#define  P2_MODE1(Mode,Pin)	do{P2M1 &= ~(Pin); P2M0 &= ~(Pin); P2M1 |= (Mode); P2M0 |= (Mode>>8);}while(0) 
#define  P3_MODE1(Mode,Pin)	do{P3M1 &= ~(Pin); P3M0 &= ~(Pin); P3M1 |= (Mode); P3M0 |= (Mode>>8);}while(0) 
#define  P4_MODE1(Mode,Pin)	do{P4M1 &= ~(Pin); P4M0 &= ~(Pin); P4M1 |= (Mode); P4M0 |= (Mode>>8);}while(0) 
#define  P5_MODE1(Mode,Pin)	do{P5M1 &= ~(Pin); P5M0 &= ~(Pin); P5M1 |= (Mode); P5M0 |= (Mode>>8);}while(0) 
#define  P6_MODE1(Mode,Pin)	do{P6M1 &= ~(Pin); P6M0 &= ~(Pin); P6M1 |= (Mode); P6M0 |= (Mode>>8);}while(0) 
#define  P7_MODE1(Mode,Pin)	do{P7M1 &= ~(Pin); P7M0 &= ~(Pin); P7M1 |= (Mode); P7M0 |= (Mode>>8);}while(0) 

#define  P0_SET_PIN_MODE(Pin_Mode)		    P0_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)	
#define  P1_SET_PIN_MODE(Pin_Mode)		    P1_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#define  P2_SET_PIN_MODE(Pin_Mode)		    P2_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#define  P3_SET_PIN_MODE(Pin_Mode)		    P3_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#define  P4_SET_PIN_MODE(Pin_Mode)		    P4_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#define  P5_SET_PIN_MODE(Pin_Mode)		    P5_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#define  P6_SET_PIN_MODE(Pin_Mode)		    P6_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#define  P7_SET_PIN_MODE(Pin_Mode)		    P7_MODE1((Pin_Mode)>>8, (Pin_Mode)&0xFF)		
#endif

/*------------------------------------------------------------------------------------

                               -------51系列风格-------

5.u8 GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);  设置IO口输入输出模式  

  使用方式：
  PnMode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);  设置IO口输入输出模式 

  P3Mode = GPIO_Mode(PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD);
                 // 设置P3口的bit.7-bit.0位，依次为PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD模式 


--------------------------------------------------------------------------------------*/
		 
#define	GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0)    ((b7<<6)&0x80)|((b6<<5)&0x40)|((b5<<4)&0x20)|((b4<<3)&0x10)|((b3<<2)&0x08)|((b2<<1)&0x04)|(b1&0x02)|((b0>>1)&0x01)|     \
  			    	 ((b7<<15)&0x8000)|((b6<<14)&0x4000)|((b5<<13)&0x2000)|((b4<<12)&0x1000)|((b3<<11)&0x0800)|((b2<<10)&0x0400)|((b1<<9)&0x0200)|((b0<<8)&0x0100)


#endif	 // END __STC_GPIO_H
