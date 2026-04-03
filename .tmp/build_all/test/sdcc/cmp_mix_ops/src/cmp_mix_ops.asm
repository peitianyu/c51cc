;--------------------------------------------------------
; File Created by SDCC : free open source ISO C Compiler
; Version 4.5.0 #15242 (MINGW64)
;--------------------------------------------------------
	.module cmp_mix_ops
	
	.optsdcc -mmcs51 --model-small
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _f_sel_PARM_3
	.globl _f_sel_PARM_2
	.globl _main
	.globl _f_sel
	.globl _f_ne
	.globl _f_eq
	.globl _f_le
	.globl _f_lt
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
	.area RSEG    (ABS,DATA)
	.org 0x0000
;--------------------------------------------------------
; special function bits
;--------------------------------------------------------
	.area RSEG    (ABS,DATA)
	.org 0x0000
;--------------------------------------------------------
; overlayable register banks
;--------------------------------------------------------
	.area REG_BANK_0	(REL,OVR,DATA)
	.ds 8
;--------------------------------------------------------
; internal ram data
;--------------------------------------------------------
	.area DSEG    (DATA)
;--------------------------------------------------------
; overlayable items in internal ram
;--------------------------------------------------------
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
_f_sel_PARM_2:
	.ds 1
_f_sel_PARM_3:
	.ds 1
;--------------------------------------------------------
; Stack segment in internal ram
;--------------------------------------------------------
	.area SSEG
__start__stack:
	.ds	1

;--------------------------------------------------------
; indirectly addressable internal ram data
;--------------------------------------------------------
	.area ISEG    (DATA)
;--------------------------------------------------------
; absolute internal ram data
;--------------------------------------------------------
	.area IABS    (ABS,DATA)
	.area IABS    (ABS,DATA)
;--------------------------------------------------------
; bit data
;--------------------------------------------------------
	.area BSEG    (BIT)
_f_le_sloc0_1_0:
	.ds 1
_f_ne_sloc0_1_0:
	.ds 1
;--------------------------------------------------------
; paged external ram data
;--------------------------------------------------------
	.area PSEG    (PAG,XDATA)
;--------------------------------------------------------
; uninitialized external ram data
;--------------------------------------------------------
	.area XSEG    (XDATA)
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area XABS    (ABS,XDATA)
;--------------------------------------------------------
; initialized external ram data
;--------------------------------------------------------
	.area XISEG   (XDATA)
	.area HOME    (CODE)
	.area GSINIT0 (CODE)
	.area GSINIT1 (CODE)
	.area GSINIT2 (CODE)
	.area GSINIT3 (CODE)
	.area GSINIT4 (CODE)
	.area GSINIT5 (CODE)
	.area GSINIT  (CODE)
	.area GSFINAL (CODE)
	.area CSEG    (CODE)
;--------------------------------------------------------
; interrupt vector
;--------------------------------------------------------
	.area HOME    (CODE)
__interrupt_vect:
	ljmp	__sdcc_gsinit_startup
; restartable atomic support routines
	.ds	5
sdcc_atomic_exchange_rollback_start::
	nop
	nop
sdcc_atomic_exchange_pdata_impl:
	movx	a, @r0
	mov	r3, a
	mov	a, r2
	movx	@r0, a
	sjmp	sdcc_atomic_exchange_exit
	nop
	nop
sdcc_atomic_exchange_xdata_impl:
	movx	a, @dptr
	mov	r3, a
	mov	a, r2
	movx	@dptr, a
	sjmp	sdcc_atomic_exchange_exit
sdcc_atomic_compare_exchange_idata_impl:
	mov	a, @r0
	cjne	a, ar2, .+#5
	mov	a, r3
	mov	@r0, a
	ret
	nop
sdcc_atomic_compare_exchange_pdata_impl:
	movx	a, @r0
	cjne	a, ar2, .+#5
	mov	a, r3
	movx	@r0, a
	ret
	nop
sdcc_atomic_compare_exchange_xdata_impl:
	movx	a, @dptr
	cjne	a, ar2, .+#5
	mov	a, r3
	movx	@dptr, a
	ret
sdcc_atomic_exchange_rollback_end::

sdcc_atomic_exchange_gptr_impl::
	jnb	b.6, sdcc_atomic_exchange_xdata_impl
	mov	r0, dpl
	jb	b.5, sdcc_atomic_exchange_pdata_impl
sdcc_atomic_exchange_idata_impl:
	mov	a, r2
	xch	a, @r0
	mov	dpl, a
	ret
sdcc_atomic_exchange_exit:
	mov	dpl, r3
	ret
sdcc_atomic_compare_exchange_gptr_impl::
	jnb	b.6, sdcc_atomic_compare_exchange_xdata_impl
	mov	r0, dpl
	jb	b.5, sdcc_atomic_compare_exchange_pdata_impl
	sjmp	sdcc_atomic_compare_exchange_idata_impl
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area HOME    (CODE)
	.area GSINIT  (CODE)
	.area GSFINAL (CODE)
	.area GSINIT  (CODE)
	.globl __sdcc_gsinit_startup
	.globl __sdcc_program_startup
	.globl __start__stack
	.globl __mcs51_genXINIT
	.globl __mcs51_genXRAMCLEAR
	.globl __mcs51_genRAMCLEAR
	.area GSFINAL (CODE)
	ljmp	__sdcc_program_startup
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area HOME    (CODE)
	.area HOME    (CODE)
__sdcc_program_startup:
	ljmp	_main
;	return from main will return to caller
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area CSEG    (CODE)
;------------------------------------------------------------
;Allocation info for local variables in function 'f_lt'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_ops.c:4: u8 f_lt(u8 i) { return i < 8; }
;	-----------------------------------------
;	 function f_lt
;	-----------------------------------------
_f_lt:
	ar7 = 0x07
	ar6 = 0x06
	ar5 = 0x05
	ar4 = 0x04
	ar3 = 0x03
	ar2 = 0x02
	ar1 = 0x01
	ar0 = 0x00
	mov	r7, dpl
	cjne	r7,#0x08,00103$
00103$:
	clr	a
	rlc	a
	mov	dpl,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'f_le'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_ops.c:5: u8 f_le(u8 i) { return i <= 8; }
;	-----------------------------------------
;	 function f_le
;	-----------------------------------------
_f_le:
	mov	a,dpl
	add	a,#0xff - 0x08
	cpl	c
	mov	_f_le_sloc0_1_0,c
	clr	a
	rlc	a
	mov	dpl,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'f_eq'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_ops.c:6: u8 f_eq(u8 i) { return i == 3; }
;	-----------------------------------------
;	 function f_eq
;	-----------------------------------------
_f_eq:
	mov	r7, dpl
	clr	a
	cjne	r7,#0x03,00103$
	inc	a
00103$:
	mov	dpl,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'f_ne'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_ops.c:7: u8 f_ne(u8 i) { return i != 3; }
;	-----------------------------------------
;	 function f_ne
;	-----------------------------------------
_f_ne:
	mov	r7, dpl
	cjne	r7,#0x03,00103$
	setb	c
	sjmp	00104$
00103$:
	clr	c
00104$:
	cpl	c
	mov	_f_ne_sloc0_1_0,c
	clr	a
	rlc	a
	mov	dpl,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'f_sel'
;------------------------------------------------------------
;a             Allocated with name '_f_sel_PARM_2'
;b             Allocated with name '_f_sel_PARM_3'
;c             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_ops.c:9: u16 f_sel(u8 c, u8 a, u8 b) {
;	-----------------------------------------
;	 function f_sel
;	-----------------------------------------
_f_sel:
;	cmp_mix_ops.c:10: return c ? a : b;
	mov	a,dpl
	jz	00103$
	mov	r7,_f_sel_PARM_2
	sjmp	00104$
00103$:
	mov	r7,_f_sel_PARM_3
00104$:
	mov	r6,#0x00
	mov	dpl, r7
	mov	dph, r6
;	cmp_mix_ops.c:11: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'main'
;------------------------------------------------------------
;	cmp_mix_ops.c:13: int main()
;	-----------------------------------------
;	 function main
;	-----------------------------------------
_main:
;	cmp_mix_ops.c:15: return 0;
	mov	dptr,#0x0000
;	cmp_mix_ops.c:16: }
	ret
	.area CSEG    (CODE)
	.area CONST   (CODE)
	.area XINIT   (CODE)
	.area CABS    (ABS,CODE)
