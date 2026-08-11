/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"STC32G_GPIO.h"
#include	"STC32G_DMA.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_LCM.h"
#include	"STC32G_Delay.h"
#include	"STC32G_Switch.h"
#include	"font.h"

/*************   功能说明   ***************

LCM接口+DMA驱动液晶屏程序

8bit I8080模式

sbit LCD_RS = P4^5;      //数据/命令切换
sbit LCD_WR = P4^2;      //写控制
sbit LCD_RD = P4^4;      //读控制
sbit LCD_CS = P3^4;      //片选
sbit LCD_RESET = P4^3;   //复位

LCM指令通过中断方式等待发送完成

DMA设置长度4096字节，通过中断方式判断传输完成

下载时, 选择时钟 22.1184MHz (可以在配置文件"config.h"中修改).

******************************************/

/*************	本地常量声明	**************/

//支持横竖屏快速定义切换
#define USE_HORIZONTAL  	  1   //定义液晶屏显示方向 	0-竖屏，1-横屏

//画笔颜色
#define WHITE         	 0xFFFF
#define BLACK         	 0x0000	  
#define BLUE             0x001F  
#define BRED             0XF81F
#define GRED             0XFFE0
#define GBLUE            0X07FF
#define RED           	 0xF800
#define MAGENTA       	 0xF81F
#define GREEN         	 0x07E0
#define CYAN          	 0x7FFF
#define YELLOW        	 0xFFE0
#define BROWN            0XBC40 //棕色
#define BRRED            0XFC07 //棕红色
#define GRAY             0X8430 //灰色

#define DMA_AMT_LEN  2047  //n+1, 不要超过芯片 xdata 空间上限

/*************	本地变量声明	**************/

u16 LCD_W;			//LCD 宽度
u16 LCD_H;			//LCD 高度

u16 POINT_COLOR=0x0000;	//画笔颜色

u16 LCM_Cnt;
u16 xdata Buffer[8]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
u16 xdata Color[DMA_AMT_LEN+1];

/*************	本地函数声明	**************/

void Test_Color(void);
void LCD_WR_DATA_16Bit(u16 Data);
void LCD_SetWindows(u16 xStar, u16 yStar,u16 xEnd,u16 yEnd);
u16 LCD_Read_ID(void);
void Show_Str(u16 x, u16 y, u16 fc, u16 bc, u8 *str,u8 size,u8 mode);
void LCD_Init(void);

/*************  外部函数和变量声明 *****************/


/******************** IO口配置 ********************/
void	GPIO_config(void)
{
	P3_MODE_OUT_PP(GPIO_Pin_4);			//P3.4口设置成推挽输出
	P4_MODE_OUT_PP(GPIO_Pin_2 | GPIO_Pin_3 | GPIO_Pin_4 | GPIO_Pin_5);	//P4.2~P4.5 设置成推挽输出

	LCM_CTRL_SW(LCM_CTRL_P45_P44_P42);	//LCM_CTRL_P45_P44_P42,LCM_CTRL_P45_P37_P36,LCM_CTRL_P40_P44_P42,LCM_CTRL_P40_P37_P36
	LCM_DATA_SW(LCM_D8_NA_P6);		//LCM_D8_NA_P2,LCM_D8_NA_P6 / LCM_D16_P2_P0,LCM_D16_P6_P2,LCM_D16_P2_P0P4,LCM_D16_P6_P7
}

/******************** LCM 配置 ********************/
void	LCM_config(void)
{
	LCM_InitTypeDef		LCM_InitStructure;		//结构定义

	LCM_InitStructure.LCM_Enable = ENABLE;				//LCM接口使能  	ENABLE,DISABLE
	LCM_InitStructure.LCM_Mode = MODE_I8080;			//LCM接口模式  	MODE_I8080,MODE_M6800
	LCM_InitStructure.LCM_Bit_Wide = BIT_WIDE_8;	//LCM数据宽度  	BIT_WIDE_8,BIT_WIDE_16
	LCM_InitStructure.LCM_Setup_Time = 2;					//LCM通信数据建立时间  	0~7
	LCM_InitStructure.LCM_Hold_Time = 1;					//LCM通信数据保持时间  	0~3
	LCM_Inilize(&LCM_InitStructure);		//初始化
	NVIC_LCM_Init(ENABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

/******************** DMA 配置 ********************/
void	DMA_config(void)
{
	DMA_LCM_InitTypeDef		DMA_LCM_InitStructure;		//结构定义

	DMA_LCM_InitStructure.DMA_Enable = ENABLE;			//DMA使能  	ENABLE,DISABLE
	DMA_LCM_InitStructure.DMA_Length = DMA_AMT_LEN;	//DMA传输总字节数  	(0~65535) + 1, 不要超过芯片 xdata 空间上限
	DMA_LCM_InitStructure.DMA_Tx_Buffer = (u16)Color;		//发送数据存储地址
	DMA_LCM_InitStructure.DMA_Rx_Buffer = (u16)Buffer;		//接收数据存储地址
	DMA_LCM_Inilize(&DMA_LCM_InitStructure);		//初始化
	NVIC_DMA_LCM_Init(ENABLE,Priority_0,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0~Priority_3; 总线优先级(低到高) Priority_0~Priority_3
}

/**********************************************/
void main(void)
{
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	LCM_config();
	DMA_config();
	EA = 1;
	LCD_Init();	//LCM初始化

	while (1)
	{
		Test_Color();
	}
}
void LCD_Fill(u16 sx,u16 sy,u16 ex,u16 ey,u16 color)
{  	
	u16 i,j;			
	u16 width=ex-sx+1; 		//得到填充的宽度
	u16 height=ey-sy+1;		//高度
	LCD_SetWindows(sx,sy,ex,ey);//设置显示窗口

	for(j=0,i=0;i<=DMA_AMT_LEN;i++)
	{
		Color[i] = color;
	}
	LCM_Cnt = 75;     //(320 * 240 * 2) / 2048 = 75
	LCD_CS=0;
	DMA_LCM_TRIG_WD();	//Write dat
//	P40 = 0;
}

void Test_Color(void)
{
	u16 lcd_id;
	u8 buf[10] = {0};

//	P40 = 0;
	LCD_Fill(0,0,LCD_W,LCD_H,WHITE);
//	P40 = 1;
	while(!LCD_CS);

	SET_LCM_DMA_LEN(0x01);		//Exe 2(n+1) bytes
	lcd_id = LCD_Read_ID();
	sprintf((char *)buf,"ID:0x%x",lcd_id);
	Show_Str(50,25,BLUE,YELLOW,buf,16,1);
	SET_LCM_DMA_LEN(DMA_AMT_LEN);		//Exe (n+1) bytes

	delay_ms(800);
//	P40 = 0;
	LCD_Fill(0,0,LCD_W,LCD_H,RED);
//	P40 = 1;
	delay_ms(800);
//	P40 = 0;
	LCD_Fill(0,0,LCD_W,LCD_H,GREEN);
//	P40 = 1;
	delay_ms(800);
//	P40 = 0;
	LCD_Fill(0,0,LCD_W,LCD_H,BLUE);
//	P40 = 1;
	delay_ms(800);
}

void Write_Cmd(unsigned char DH,unsigned char DL)
{
	SET_LCM_DAT_LOW(DH);
	LCD_CS = 0;
	LcmFlag = 1;
	LCM_WRITE_CMD();		//Enable interface, write command out
	while(LcmFlag);
	
	SET_LCM_DAT_LOW(DL);
	LcmFlag = 1;
	LCM_WRITE_CMD();		//Enable interface, write command out
	while(LcmFlag);
	LCD_CS = 1 ;
}

void Write_Data(unsigned char DH,unsigned char DL)
{
	SET_LCM_DAT_LOW(DH);
	LCD_CS = 0;
	LcmFlag = 1;
	LCM_WRITE_DAT();		//Enable interface, write data out
	while(LcmFlag);
	
	SET_LCM_DAT_LOW(DL);
	LcmFlag = 1;
	LCM_WRITE_DAT();		//Enable interface, write data out
	while(LcmFlag);
	LCD_CS = 1 ;
}

void LCD_WR_REG(u8 Reg)
{	
	SET_LCM_DAT_LOW(Reg);
	LCD_CS = 0;
	LcmFlag = 1;
	LCM_WRITE_CMD();		//Enable interface, write command out
	while(LcmFlag);
	LCD_CS = 1 ;
}

u16 LCD_RD_DATA(void)
{
	//DMA Read
	LCD_CS=0;
	DmaLcmFlag = 1;
	DMA_LCM_TRIG_RD();	//Read data
	while(DmaLcmFlag);
	LCD_CS=1;
	return (Buffer[0]);
}

void LCD_WR_REG16(u8 Reg, u16 dat)
{	
	Write_Cmd(0x00,Reg);
	Write_Data((dat>>8)&0xFF,dat&0xFF);
}

void LCD_WR_DATA_16Bit(u16 Data)
{
	Write_Data((Data>>8)&0xFF,Data&0xFF);
}

/*****************************************************************************
 * @name       :u16 LCD_Read_ID(void)
 * @date       :2020-12-11 
 * @function   :Read ID
 * @parameters :None
 * @retvalue   :ID value
******************************************************************************/ 
u16 LCD_Read_ID(void)
{
	u16 val;

	LCD_WR_REG(0x00);		//ID: Status Read (RS)
	val = LCD_RD_DATA();
	return (val);
}

/*****************************************************************************
 * @name       :void LCDReset(void)
 * @date       :2018-08-09 
 * @function   :Reset LCD screen
 * @parameters :None
 * @retvalue   :None
******************************************************************************/	
void LCDReset(void)
{
	LCD_CS=1;
	delay_ms(50);	
	LCD_RESET=0;
	delay_ms(150);
	LCD_RESET=1;
	delay_ms(50);
}

/*****************************************************************************
 * @name       :void LCD_Init(void)
 * @date       :2018-08-09 
 * @function   :Initialization LCD screen
 * @parameters :None
 * @retvalue   :None
******************************************************************************/	 	 
void LCD_Init(void)
{
	LCDReset(); //初始化之前复位
	delay_ms(150);                     //根据不同晶振速度可以调整延时，保障稳定显示
//*************2.4inch ILI9325初始化**********//	
	LCD_WR_REG16(0x00E5,0x78F0); 
	LCD_WR_REG16(0x0001,0x0100); 
	LCD_WR_REG16(0x0002,0x0700); 
	LCD_WR_REG16(0x0003,0x1030); 
	LCD_WR_REG16(0x0004,0x0000); 
	LCD_WR_REG16(0x0008,0x0202);  
	LCD_WR_REG16(0x0009,0x0000);
	LCD_WR_REG16(0x000A,0x0000); 
	LCD_WR_REG16(0x000C,0x0000); 
	LCD_WR_REG16(0x000D,0x0000);
	LCD_WR_REG16(0x000F,0x0000);
	//power on sequence VGHVGL
	LCD_WR_REG16(0x0010,0x0000);   
	LCD_WR_REG16(0x0011,0x0007);  
	LCD_WR_REG16(0x0012,0x0000);  
	LCD_WR_REG16(0x0013,0x0000); 
	LCD_WR_REG16(0x0007,0x0000); 
	//vgh 
	LCD_WR_REG16(0x0010,0x1690);   
	LCD_WR_REG16(0x0011,0x0227);
	delay_ms(10);
	//vregiout 
	LCD_WR_REG16(0x0012,0x009D); //0x001b
	delay_ms(10); 
	//vom amplitude
	LCD_WR_REG16(0x0013,0x1900);
	delay_ms(10); 
	//vom H
	LCD_WR_REG16(0x0029,0x0025); 
	LCD_WR_REG16(0x002B,0x000D); 
	//gamma
	LCD_WR_REG16(0x0030,0x0007);
	LCD_WR_REG16(0x0031,0x0303);
	LCD_WR_REG16(0x0032,0x0003); //0006
	LCD_WR_REG16(0x0035,0x0206);
	LCD_WR_REG16(0x0036,0x0008);
	LCD_WR_REG16(0x0037,0x0406); 
	LCD_WR_REG16(0x0038,0x0304); //0200
	LCD_WR_REG16(0x0039,0x0007); 
	LCD_WR_REG16(0x003C,0x0602); //0504
	LCD_WR_REG16(0x003D,0x0008); 
	//ram
	LCD_WR_REG16(0x0050,0x0000); 
	LCD_WR_REG16(0x0051,0x00EF);
	LCD_WR_REG16(0x0052,0x0000); 
	LCD_WR_REG16(0x0053,0x013F);  
	LCD_WR_REG16(0x0060,0xA700); 
	LCD_WR_REG16(0x0061,0x0001); 
	LCD_WR_REG16(0x006A,0x0000); 
	//
	LCD_WR_REG16(0x0080,0x0000); 
	LCD_WR_REG16(0x0081,0x0000); 
	LCD_WR_REG16(0x0082,0x0000); 
	LCD_WR_REG16(0x0083,0x0000); 
	LCD_WR_REG16(0x0084,0x0000); 
	LCD_WR_REG16(0x0085,0x0000); 
	//
	LCD_WR_REG16(0x0090,0x0010); 
	LCD_WR_REG16(0x0092,0x0600); 
	
	LCD_WR_REG16(0x0007,0x0133);
	LCD_WR_REG16(0x0000,0x0022);

	//设置LCD属性参数
	#if USE_HORIZONTAL==1
	LCD_W = 320;
	LCD_H = 240;
	LCD_WR_REG16(0x0003, 0x1038); // set GRAM write direction and BGR=1.
	LCD_WR_REG16(0x0001, 0x0000); // set SS and SM bit
	#else
	LCD_W = 240;
	LCD_H = 320;
	LCD_WR_REG16(0x0003, 0x1030); // set GRAM write direction and BGR=1.
	LCD_WR_REG16(0x0001, 0x0100); // set SS and SM bit
	#endif 
}

#define WINDOW_XADDR_START	0x0050 // Horizontal Start Address Set
#define WINDOW_XADDR_END	0x0051 // Horizontal End Address Set
#define WINDOW_YADDR_START	0x0052 // Vertical Start Address Set
#define WINDOW_YADDR_END	0x0053 // Vertical End Address Set
#define GRAM_XADDR		    0x0020 // GRAM Horizontal Address Set
#define GRAM_YADDR		    0x0021 // GRAM Vertical Address Set
#define GRAMWR 			    0x0022 // memory write

void LCD_SetWindows(u16 xStar0, u16 yStar0,u16 xEnd0,u16 yEnd0)
{	
	u16 xStar; u16 yStar;u16 xEnd;u16 yEnd;
	#if USE_HORIZONTAL==1
	xStar = yStar0;
	xEnd = yEnd0;
	yStar = xStar0;
	yEnd = xEnd0;
	#else
	xStar = xStar0;
	xEnd = xEnd0;
	yStar = yStar0;
	yEnd = yEnd0;
	#endif 

  LCD_WR_REG16(WINDOW_XADDR_START,xStar);
  LCD_WR_REG16(WINDOW_XADDR_END,xEnd);
  LCD_WR_REG16(WINDOW_YADDR_START,yStar);
  LCD_WR_REG16(WINDOW_YADDR_END,yEnd);
  LCD_WR_REG16(GRAM_XADDR,xStar);
  LCD_WR_REG16(GRAM_YADDR,yStar);
//	LCD_WR_REG(GRAMWR);
  Write_Cmd( (GRAMWR>>8)&0xFF, GRAMWR&0xFF ); //16bit
}

/*****************************************************************************
 * @name       :void LCD_DrawPoint(u16 x,u16 y)
 * @date       :2018-08-09 
 * @function   :Write a pixel data at a specified location
 * @parameters :x:the x coordinate of the pixel
                y:the y coordinate of the pixel
 * @retvalue   :None
******************************************************************************/	
void LCD_DrawPoint(u16 x,u16 y)
{
	LCD_SetWindows(x,y,x,y);//设置光标位置
	LCD_WR_DATA_16Bit(POINT_COLOR);
} 	 

/*****************************************************************************
 * @name       :void LCD_ShowChar(u16 x,u16 y,u16 fc, u16 bc, u8 num,u8 size,u8 mode)
 * @date       :2018-08-09 
 * @function   :Display a single English character
 * @parameters :x:the beginning x coordinate of the Character display position
                y:the beginning y coordinate of the Character display position
								fc:the color value of display character
								bc:the background color of display character
								num:the ascii code of display character(0~94)
								size:the size of display character
								mode:0-no overlying,1-overlying
 * @retvalue   :None
******************************************************************************/ 
void LCD_ShowChar(u16 x,u16 y,u16 fc, u16 bc, u8 num,u8 size,u8 mode)
{
	u8 temp;
	u8 pos,t;
	u16 colortemp=POINT_COLOR;

	num=num-' ';//得到偏移后的值
	LCD_SetWindows(x,y,x+size/2-1,y+size-1);//设置单个文字显示窗口
	if(!mode) //非叠加方式
	{
		for(pos=0;pos<size;pos++)
		{
			if(size==12)temp=asc2_1206[num][pos];//调用1206字体
			else temp=asc2_1608[num][pos];		 //调用1608字体
			for(t=0;t<size/2;t++)
			{
				if(temp&0x01)LCD_WR_DATA_16Bit(fc); 
				else LCD_WR_DATA_16Bit(bc); 
				temp>>=1; 
			}
		}
	}
	else//叠加方式
	{
		for(pos=0;pos<size;pos++)
		{
			if(size==12)temp=asc2_1206[num][pos];//调用1206字体
			else temp=asc2_1608[num][pos];		 //调用1608字体
			for(t=0;t<size/2;t++)
			{
				POINT_COLOR=fc;
				if(temp&0x01)	LCD_DrawPoint(x+t,y+pos);//画一个点
				temp>>=1;
			}
		}
	}
	POINT_COLOR=colortemp;	
	LCD_SetWindows(0,0,LCD_W-1,LCD_H-1);//恢复窗口为全屏    	   	 	  
}

/*****************************************************************************
 * @name       :void Show_Str(u16 x, u16 y, u16 fc, u16 bc, u8 *str,u8 size,u8 mode)
 * @date       :2018-08-09 
 * @function   :Display Chinese and English strings
 * @parameters :x:the beginning x coordinate of the Chinese and English strings
                y:the beginning y coordinate of the Chinese and English strings
								fc:the color value of Chinese and English strings
								bc:the background color of Chinese and English strings
								str:the start address of the Chinese and English strings
								size:the size of Chinese and English strings
								mode:0-no overlying,1-overlying
 * @retvalue   :None
******************************************************************************/	   		   
void Show_Str(u16 x, u16 y, u16 fc, u16 bc, u8 *str,u8 size,u8 mode)
{					
	u16 x0=x;							  	  
	u8 bHz=0;     //字符或者中文 
	while(*str!=0)//数据未结束
	{ 
		if(!bHz)
		{
			if(x>(LCD_W-size/2)||y>(LCD_H-size)) 
			return;
			if(*str>0x80)	bHz=1;//中文 
			else              //字符
			{
				if(*str==0x0D)//换行符号
				{
					y+=size;
					x=x0;
					str++;
				}
				else
				{
					if(size>16)//字库中没有集成12X24 16X32的英文字体,用8X16代替
					{  
						LCD_ShowChar(x,y,fc,bc,*str,16,mode);
						x+=8; //字符,为全字的一半 
					}
					else
					{
						LCD_ShowChar(x,y,fc,bc,*str,size,mode);
						x+=size/2; //字符,为全字的一半 
					}
				}
				str++;
			}
		}
		else//中文
		{
//			if(x>(lcddev.width-size)||y>(lcddev.height-size))
//			return;
//			bHz=0;//有汉字库
//			if(size==32)
//			GUI_DrawFont32(x,y,fc,bc,str,mode);
//			else if(size==24)
//			GUI_DrawFont24(x,y,fc,bc,str,mode);
//			else
//			GUI_DrawFont16(x,y,fc,bc,str,mode);

			str+=2;
			x+=size;//下一个汉字偏移
		}
	}
}

