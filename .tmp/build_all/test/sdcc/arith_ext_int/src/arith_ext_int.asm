;--------------------------------------------------------
; File Created by SDCC : free open source ISO C Compiler
; Version 4.5.0 #15242 (MINGW64)
;--------------------------------------------------------
	.module arith_ext_int
	
	.optsdcc -mmcs51 --model-small
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _mixed_unsigned_signed_PARM_2
	.globl _mixed_signed_unsigned_PARM_2
	.globl _shr_unsigned_PARM_2
	.globl _shr_signed_PARM_2
	.globl _shl_int_PARM_2
	.globl _sub_borrow_unsigned_PARM_2
	.globl _sub_borrow_signed_PARM_2
	.globl _add_overflow_unsigned_PARM_2
	.globl _add_overflow_signed_PARM_2
	.globl _main
	.globl _sub_min_max
	.globl _add_min_max
	.globl _mixed_unsigned_signed
	.globl _mixed_signed_unsigned
	.globl _shr_unsigned
	.globl _shr_signed
	.globl _shl_int
	.globl _mod_unsigned
	.globl _div_unsigned
	.globl _mod_signed
	.globl _div_signed
	.globl _mul_unsigned
	.globl _mul_signed
	.globl _sub_borrow_unsigned
	.globl _sub_borrow_signed
	.globl _addu_with_const
	.globl _add_with_const
	.globl _add_overflow_unsigned
	.globl _add_overflow_signed
	.globl _mod_unsigned_PARM_2
	.globl _div_unsigned_PARM_2
	.globl _mod_signed_PARM_2
	.globl _div_signed_PARM_2
	.globl _mul_unsigned_PARM_2
	.globl _mul_signed_PARM_2
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
_mul_signed_PARM_2:
	.ds 2
_mul_unsigned_PARM_2:
	.ds 2
_div_signed_PARM_2:
	.ds 2
_mod_signed_PARM_2:
	.ds 2
_div_unsigned_PARM_2:
	.ds 2
_mod_unsigned_PARM_2:
	.ds 2
;--------------------------------------------------------
; overlayable items in internal ram
;--------------------------------------------------------
	.area	OSEG    (OVR,DATA)
_add_overflow_signed_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_add_overflow_unsigned_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
_sub_borrow_signed_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_sub_borrow_unsigned_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_shl_int_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_shr_signed_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_shr_unsigned_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_mixed_signed_unsigned_PARM_2:
	.ds 2
	.area	OSEG    (OVR,DATA)
_mixed_unsigned_signed_PARM_2:
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
;Allocation info for local variables in function 'add_overflow_signed'
;------------------------------------------------------------
;b             Allocated with name '_add_overflow_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:1: int add_overflow_signed(int a,int b){ return a + b; }
;	-----------------------------------------
;	 function add_overflow_signed
;	-----------------------------------------
_add_overflow_signed:
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
	mov	a,_add_overflow_signed_PARM_2
	add	a, r6
	mov	dpl,a
	mov	a,(_add_overflow_signed_PARM_2 + 1)
	addc	a, r7
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'add_overflow_unsigned'
;------------------------------------------------------------
;b             Allocated with name '_add_overflow_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:2: unsigned int add_overflow_unsigned(unsigned int a,unsigned int b){ return a + b; }
;	-----------------------------------------
;	 function add_overflow_unsigned
;	-----------------------------------------
_add_overflow_unsigned:
	mov	r6, dpl
	mov	r7, dph
	mov	a,_add_overflow_unsigned_PARM_2
	add	a, r6
	mov	dpl,a
	mov	a,(_add_overflow_unsigned_PARM_2 + 1)
	addc	a, r7
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'add_with_const'
;------------------------------------------------------------
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:4: int add_with_const(int a){ return a + 32767; }
;	-----------------------------------------
;	 function add_with_const
;	-----------------------------------------
_add_with_const:
	mov	r6, dpl
	mov	r7, dph
	mov	a,#0xff
	add	a, r6
	mov	dpl,a
	mov	a,#0x7f
	addc	a, r7
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'addu_with_const'
;------------------------------------------------------------
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:5: unsigned int addu_with_const(unsigned int a){ return a + (unsigned int)65535; }
;	-----------------------------------------
;	 function addu_with_const
;	-----------------------------------------
_addu_with_const:
	mov	r6, dpl
	mov	r7, dph
	mov	a,#0xff
	add	a, r6
	mov	dpl,a
	mov	a,#0xff
	addc	a, r7
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'sub_borrow_signed'
;------------------------------------------------------------
;b             Allocated with name '_sub_borrow_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:7: int sub_borrow_signed(int a,int b){ return a - b; }
;	-----------------------------------------
;	 function sub_borrow_signed
;	-----------------------------------------
_sub_borrow_signed:
	mov	r6, dpl
	mov	r7, dph
	mov	a,r6
	clr	c
	subb	a,_sub_borrow_signed_PARM_2
	mov	dpl,a
	mov	a,r7
	subb	a,(_sub_borrow_signed_PARM_2 + 1)
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'sub_borrow_unsigned'
;------------------------------------------------------------
;b             Allocated with name '_sub_borrow_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:8: unsigned int sub_borrow_unsigned(unsigned int a,unsigned int b){ return a - b; }
;	-----------------------------------------
;	 function sub_borrow_unsigned
;	-----------------------------------------
_sub_borrow_unsigned:
	mov	r6, dpl
	mov	r7, dph
	mov	a,r6
	clr	c
	subb	a,_sub_borrow_unsigned_PARM_2
	mov	dpl,a
	mov	a,r7
	subb	a,(_sub_borrow_unsigned_PARM_2 + 1)
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'mul_signed'
;------------------------------------------------------------
;b             Allocated with name '_mul_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:10: int mul_signed(int a,int b){ return a * b; }
;	-----------------------------------------
;	 function mul_signed
;	-----------------------------------------
_mul_signed:
	mov	__mulint_PARM_2,_mul_signed_PARM_2
	mov	(__mulint_PARM_2 + 1),(_mul_signed_PARM_2 + 1)
	ljmp	__mulint
;------------------------------------------------------------
;Allocation info for local variables in function 'mul_unsigned'
;------------------------------------------------------------
;b             Allocated with name '_mul_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:11: unsigned int mul_unsigned(unsigned int a,unsigned int b){ return a * b; }
;	-----------------------------------------
;	 function mul_unsigned
;	-----------------------------------------
_mul_unsigned:
	mov	__mulint_PARM_2,_mul_unsigned_PARM_2
	mov	(__mulint_PARM_2 + 1),(_mul_unsigned_PARM_2 + 1)
	ljmp	__mulint
;------------------------------------------------------------
;Allocation info for local variables in function 'div_signed'
;------------------------------------------------------------
;b             Allocated with name '_div_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:13: int div_signed(int a,int b){ return a / b; }
;	-----------------------------------------
;	 function div_signed
;	-----------------------------------------
_div_signed:
	mov	__divsint_PARM_2,_div_signed_PARM_2
	mov	(__divsint_PARM_2 + 1),(_div_signed_PARM_2 + 1)
	ljmp	__divsint
;------------------------------------------------------------
;Allocation info for local variables in function 'mod_signed'
;------------------------------------------------------------
;b             Allocated with name '_mod_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:14: int mod_signed(int a,int b){ return a % b; }
;	-----------------------------------------
;	 function mod_signed
;	-----------------------------------------
_mod_signed:
	mov	__modsint_PARM_2,_mod_signed_PARM_2
	mov	(__modsint_PARM_2 + 1),(_mod_signed_PARM_2 + 1)
	ljmp	__modsint
;------------------------------------------------------------
;Allocation info for local variables in function 'div_unsigned'
;------------------------------------------------------------
;b             Allocated with name '_div_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:15: unsigned int div_unsigned(unsigned int a,unsigned int b){ return a / b; }
;	-----------------------------------------
;	 function div_unsigned
;	-----------------------------------------
_div_unsigned:
	mov	__divuint_PARM_2,_div_unsigned_PARM_2
	mov	(__divuint_PARM_2 + 1),(_div_unsigned_PARM_2 + 1)
	ljmp	__divuint
;------------------------------------------------------------
;Allocation info for local variables in function 'mod_unsigned'
;------------------------------------------------------------
;b             Allocated with name '_mod_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:16: unsigned int mod_unsigned(unsigned int a,unsigned int b){ return a % b; }
;	-----------------------------------------
;	 function mod_unsigned
;	-----------------------------------------
_mod_unsigned:
	mov	__moduint_PARM_2,_mod_unsigned_PARM_2
	mov	(__moduint_PARM_2 + 1),(_mod_unsigned_PARM_2 + 1)
	ljmp	__moduint
;------------------------------------------------------------
;Allocation info for local variables in function 'shl_int'
;------------------------------------------------------------
;c             Allocated with name '_shl_int_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:18: int shl_int(int a,int c){ return a << c; }
;	-----------------------------------------
;	 function shl_int
;	-----------------------------------------
_shl_int:
	mov	r6, dpl
	mov	r7, dph
	mov	b,_shl_int_PARM_2
	inc	b
	mov	dpl,ar6
	mov	dph,ar7
	sjmp	00104$
00103$:
	mov	a,dpl
	add	a,dpl
	mov	dpl,a
	mov	a,dph
	rlc	a
	mov	dph,a
00104$:
	djnz	b,00103$
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'shr_signed'
;------------------------------------------------------------
;c             Allocated with name '_shr_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:19: int shr_signed(int a,int c){ return a >> c; }
;	-----------------------------------------
;	 function shr_signed
;	-----------------------------------------
_shr_signed:
	mov	r6, dpl
	mov	r7, dph
	mov	b,_shr_signed_PARM_2
	inc	b
	mov	dpl,ar6
	mov	dph,ar7
	mov	a,r7
	rlc	a
	mov	ov,c
	sjmp	00104$
00103$:
	mov	c,ov
	mov	a,dph
	rrc	a
	mov	dph,a
	mov	a,dpl
	rrc	a
	mov	dpl,a
00104$:
	djnz	b,00103$
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'shr_unsigned'
;------------------------------------------------------------
;c             Allocated with name '_shr_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:20: unsigned int shr_unsigned(unsigned int a,int c){ return a >> c; }
;	-----------------------------------------
;	 function shr_unsigned
;	-----------------------------------------
_shr_unsigned:
	mov	r6, dpl
	mov	r7, dph
	mov	b,_shr_unsigned_PARM_2
	inc	b
	mov	dpl,ar6
	mov	dph,ar7
	sjmp	00104$
00103$:
	clr	c
	mov	a,dph
	rrc	a
	mov	dph,a
	mov	a,dpl
	rrc	a
	mov	dpl,a
00104$:
	djnz	b,00103$
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'mixed_signed_unsigned'
;------------------------------------------------------------
;b             Allocated with name '_mixed_signed_unsigned_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:22: int mixed_signed_unsigned(int a,unsigned int b){ return a + b; }
;	-----------------------------------------
;	 function mixed_signed_unsigned
;	-----------------------------------------
_mixed_signed_unsigned:
	mov	r6, dpl
	mov	r7, dph
	mov	a,_mixed_signed_unsigned_PARM_2
	add	a, r6
	mov	dpl,a
	mov	a,(_mixed_signed_unsigned_PARM_2 + 1)
	addc	a, r7
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'mixed_unsigned_signed'
;------------------------------------------------------------
;b             Allocated with name '_mixed_unsigned_signed_PARM_2'
;a             Allocated to registers r6 r7 
;------------------------------------------------------------
;	arith_ext_int.c:23: unsigned int mixed_unsigned_signed(unsigned int a,int b){ return a + b; }
;	-----------------------------------------
;	 function mixed_unsigned_signed
;	-----------------------------------------
_mixed_unsigned_signed:
	mov	r6, dpl
	mov	r7, dph
	mov	r4,_mixed_unsigned_signed_PARM_2
	mov	r5,(_mixed_unsigned_signed_PARM_2 + 1)
	mov	a,r4
	add	a, r6
	mov	dpl,a
	mov	a,r5
	addc	a, r7
	mov	dph,a
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'add_min_max'
;------------------------------------------------------------
;	arith_ext_int.c:25: int add_min_max(){ return 32767 + 1; }
;	-----------------------------------------
;	 function add_min_max
;	-----------------------------------------
_add_min_max:
	mov	dptr,#0x8000
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'sub_min_max'
;------------------------------------------------------------
;	arith_ext_int.c:26: int sub_min_max(){ return (-32768) - 1; }
;	-----------------------------------------
;	 function sub_min_max
;	-----------------------------------------
_sub_min_max:
	mov	dptr,#0x7fff
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'main'
;------------------------------------------------------------
;	arith_ext_int.c:29: int main()
;	-----------------------------------------
;	 function main
;	-----------------------------------------
_main:
;	arith_ext_int.c:31: return 0;
	mov	dptr,#0x0000
;	arith_ext_int.c:32: }
	ret
	.area CSEG    (CODE)
	.area CONST   (CODE)
	.area XINIT   (CODE)
	.area CABS    (ABS,CODE)
