; C51CC Startup file
; Placed at code address 0x0000 by the linker (first object in link order).
;
; Actions:
;   1. Clear internal data memory (IDATA) from 0x7F down to 0x00
;   2. Initialise stack pointer SP = 0x07
;   3. Jump to _main
;
; Compatible with c51cc assembler / normalize_startup_script filter:
;   - No NAME / RSEG / SEGMENT / ORG / END directives
;   - Standard 8051 mnemonics only
;   - Labels end with ':'

?C_STARTUP:
    MOV R0, #07FH
    CLR A
?C_IDATALOOP:
    MOV @R0, A
    DJNZ R0, ?C_IDATALOOP
    MOV SP, #07H
    LJMP _main
