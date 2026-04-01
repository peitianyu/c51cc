#ifndef __INTRINS_H__
#define __INTRINS_H__

#ifndef _nop_
#define _nop_() ((void)0)
#endif

#ifndef _crol_
#define _crol_(value, shift) ((unsigned char)((((unsigned char)(value)) << ((shift) & 7)) | (((unsigned char)(value)) >> ((8 - ((shift) & 7)) & 7))))
#endif

#endif
