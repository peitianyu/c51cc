NAME    STARTUP

?C_STARTUP  SEGMENT   CODE
			ORG       0
			LJMP      STARTUP1

			RSEG      ?C_STARTUP
STARTUP1:
			MOV       SP, #07H
			CLR       A
			MOV       R0, #07FH
IDATA_LOOP:
			MOV       @R0, A
			DJNZ      R0, IDATA_LOOP
			MOV       00H, A

			MOV       DPTR, #0000H
			MOV       R7, #0FFH
XDATA_PAGE:
			MOV       R6, #0FFH
XDATA_LOOP:
			MOVX      @DPTR, A
			INC       DPTR
			DJNZ      R6, XDATA_LOOP
			DJNZ      R7, XDATA_PAGE
			LCALL     main
HALT:
			SJMP      HALT