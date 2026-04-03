;--------------------------------------------------------
; File Created by SDCC : free open source ISO C Compiler
; Version 4.5.0 #15242 (MINGW64)
;--------------------------------------------------------
	.module cmp_signed_int
	
	.optsdcc -mmcs51 --model-small
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _cmp_signed_ne_PARM_2
	.globl _cmp_signed_eq_PARM_2
	.globl _cmp_signed_ge_PARM_2
	.globl _cmp_signed_gt_PARM_2
	.globl _cmp_signed_le_PARM_2
	.globl _cmp_signed_lt_PARM_2
	.globl _main
	.globl _cmp_signed_ne
	.globl _cmp_signed_eq
	.globl _cmp_signed_ge
	.globl _cmp_signed_gt
	.globl _cmp_signed_le
	.globl _cmp_signed_lt
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
_cmp_signed_lt_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_cmp_signed_le_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_cmp_signed_gt_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_cmp_signed_ge_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_cmp_signed_eq_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_cmp_signed_ne_PARM_2:
	.ds 2
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
_cmp_signed_le_sloc0_1_0:
	.ds 1
_cmp_signed_ge_sloc0_1_0:
	.ds 1
_cmp_signed_ne_sloc0_1_0:
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
;Allocation info for local variables in function 'cmp_signed_lt'
;------------------------------------------------------------
;b             Allocated with name '_cmp_signed_lt_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	cmp_signed_int.c:1: int cmp_signed_lt(int a,int b){ return a < b; }
;	-----------------------------------------
;	 function cmp_signed_lt
;	-----------------------------------------
_cmp_signed_lt:
	ar7 = 0x07
	ar6 = 0x06
	ar5 = 0x05
	ar4 = 0x04
	ar3 = 0x03
	ar2 = 0x02
	ar1 = 0x01
	ar0 = 0x00
	mov	r6, dpl
	mov	r7, dph
	clr	c
	mov	a,r6
	subb	a,_cmp_signed_lt_PARM_2
	mov	a,r7
	xrl	a,#0x80
	mov	b,(_cmp_signed_lt_PARM_2 + 1)
	xrl	b,#0x80
	subb	a,b
	clr	a
	rlc	a
	mov	r6,a
	mov	r7,#0x00
	mov	dpl, r6
	mov	dph, r7
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'cmp_signed_le'
;------------------------------------------------------------
;b             Allocated with name '_cmp_signed_le_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	cmp_signed_int.c:2: int cmp_signed_le(int a,int b){ return a <= b; }
;	-----------------------------------------
;	 function cmp_signed_le
;	-----------------------------------------
_cmp_signed_le:
	mov	r6, dpl
	mov	r7, dph
	clr	c
	mov	a,_cmp_signed_le_PARM_2
	subb	a,r6
	mov	a,(_cmp_signed_le_PARM_2 + 1)
	xrl	a,#0x80
	mov	b,r7
	xrl	b,#0x80
	subb	a,b
	cpl	c
	mov	_cmp_signed_le_sloc0_1_0,c
	clr	a
	rlc	a
	mov	r6,a
	mov	r7,#0x00
	mov	dpl, r6
	mov	dph, r7
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'cmp_signed_gt'
;------------------------------------------------------------
;b             Allocated with name '_cmp_signed_gt_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	cmp_signed_int.c:3: int cmp_signed_gt(int a,int b){ return a > b; }
;	-----------------------------------------
;	 function cmp_signed_gt
;	-----------------------------------------
_cmp_signed_gt:
	mov	r6, dpl
	mov	r7, dph
	clr	c
	mov	a,_cmp_signed_gt_PARM_2
	subb	a,r6
	mov	a,(_cmp_signed_gt_PARM_2 + 1)
	xrl	a,#0x80
	mov	b,r7
	xrl	b,#0x80
	subb	a,b
	clr	a
	rlc	a
	mov	r6,a
	mov	r7,#0x00
	mov	dpl, r6
	mov	dph, r7
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'cmp_signed_ge'
;------------------------------------------------------------
;b             Allocated with name '_cmp_signed_ge_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	cmp_signed_int.c:4: int cmp_signed_ge(int a,int b){ return a >= b; }
;	-----------------------------------------
;	 function cmp_signed_ge
;	-----------------------------------------
_cmp_signed_ge:
	mov	r6, dpl
	mov	r7, dph
	clr	c
	mov	a,r6
	subb	a,_cmp_signed_ge_PARM_2
	mov	a,r7
	xrl	a,#0x80
	mov	b,(_cmp_signed_ge_PARM_2 + 1)
	xrl	b,#0x80
	subb	a,b
	cpl	c
	mov	_cmp_signed_ge_sloc0_1_0,c
	clr	a
	rlc	a
	mov	r6,a
	mov	r7,#0x00
	mov	dpl, r6
	mov	dph, r7
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'cmp_signed_eq'
;------------------------------------------------------------
;b             Allocated with name '_cmp_signed_eq_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	cmp_signed_int.c:5: int cmp_signed_eq(int a,int b){ return a == b; }
;	-----------------------------------------
;	 function cmp_signed_eq
;	-----------------------------------------
_cmp_signed_eq:
	mov	r6, dpl
	mov	r7, dph
	mov	a,r6
	cjne	a,_cmp_signed_eq_PARM_2,00103$
	mov	a,r7
	cjne	a,(_cmp_signed_eq_PARM_2 + 1),00103$
	mov	a,#0x01
	sjmp	00104$
00103$:
	clr	a
00104$:
	mov	r6,a
	mov	r7,#0x00
	mov	dpl, r6
	mov	dph, r7
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'cmp_signed_ne'
;------------------------------------------------------------
;b             Allocated with name '_cmp_signed_ne_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	cmp_signed_int.c:6: int cmp_signed_ne(int a,int b){ return a != b; }
;	-----------------------------------------
;	 function cmp_signed_ne
;	-----------------------------------------
_cmp_signed_ne:
	mov	r6, dpl
	mov	r7, dph
	mov	a,r6
	cjne	a,_cmp_signed_ne_PARM_2,00103$
	mov	a,r7
	cjne	a,(_cmp_signed_ne_PARM_2 + 1),00103$
	setb	c
	sjmp	00104$
00103$:
	clr	c
00104$:
	cpl	c
	mov	_cmp_signed_ne_sloc0_1_0,c
	clr	a
	rlc	a
	mov	r6,a
	mov	r7,#0x00
	mov	dpl, r6
	mov	dph, r7
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'main'
;------------------------------------------------------------
;	cmp_signed_int.c:8: int main()
;	-----------------------------------------
;	 function main
;	-----------------------------------------
_main:
;	cmp_signed_int.c:10: return 0;
	mov	dptr,#0x0000
;	cmp_signed_int.c:11: }
	ret
	.area CSEG    (CODE)
	.area CONST   (CODE)
	.area XINIT   (CODE)
	.area CABS    (ABS,CODE)
