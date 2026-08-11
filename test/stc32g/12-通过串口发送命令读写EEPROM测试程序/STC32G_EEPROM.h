/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#ifndef	__STC32G_EEPROM_H
#define	__STC32G_EEPROM_H

#include	"config.h"

//========================================================================
//                              ∂®“Â…˘√˜
//========================================================================


//========================================================================
//                               IAP…Ë÷√
//========================================================================

#define		IAP_STANDBY()	IAP_CMD = 0		//IAPø’œ–√¸¡Ó£®Ω˚÷π£©
#define		IAP_READ()		IAP_CMD = 1		//IAP∂¡≥ˆ√¸¡Ó
#define		IAP_WRITE()		IAP_CMD = 2		//IAP–¥»Î√¸¡Ó
#define		IAP_ERASE()		IAP_CMD = 3		//IAP≤¡≥˝√¸¡Ó

#define	IAP_ENABLE()		IAPEN = 1; IAP_TPS = MAIN_Fosc / 1000000
#define	IAP_DISABLE()		IAP_CONTR = 0; IAP_CMD = 0; IAP_TRIG = 0; IAP_ADDRH = 0xff; IAP_ADDRL = 0xff


void	DisableEEPROM(void);
void 	EEPROM_read_n(u32 EE_address,u8 *DataAddress,u16 number);
void 	EEPROM_write_n(u32 EE_address,u8 *DataAddress,u16 number);
void	EEPROM_SectorErase(u32 EE_address);


#endif