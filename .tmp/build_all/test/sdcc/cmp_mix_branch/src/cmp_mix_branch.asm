;--------------------------------------------------------
; File Created by SDCC : free open source ISO C Compiler
; Version 4.5.0 #15242 (MINGW64)
;--------------------------------------------------------
	.module cmp_mix_branch
	
	.optsdcc -mmcs51 --model-small
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _loop_lt
	.globl _b_ne
	.globl _b_eq
	.globl _b_le
	.globl _b_lt
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
;Allocation info for local variables in function 'b_lt'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_branch.c:4: u8 b_lt(u8 i) {
;	-----------------------------------------
;	 function b_lt
;	-----------------------------------------
_b_lt:
	ar7 = 0x07
	ar6 = 0x06
	ar5 = 0x05
	ar4 = 0x04
	ar3 = 0x03
	ar2 = 0x02
	ar1 = 0x01
	ar0 = 0x00
	mov	r7, dpl
;	cmp_mix_branch.c:5: if ((u16)i < 8) return 1;
	cjne	r7,#0x08,00111$
00111$:
	jnc	00102$
	mov	dpl, #0x01
	ret
00102$:
;	cmp_mix_branch.c:6: return 0;
	mov	dpl, #0x00
;	cmp_mix_branch.c:7: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'b_le'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_branch.c:9: u8 b_le(u8 i) {
;	-----------------------------------------
;	 function b_le
;	-----------------------------------------
_b_le:
;	cmp_mix_branch.c:10: if ((u16)i <= 8) return 1;
	mov	a,dpl
	add	a,#0xff - 0x08
	jc	00102$
	mov	dpl, #0x01
	ret
00102$:
;	cmp_mix_branch.c:11: return 0;
	mov	dpl, #0x00
;	cmp_mix_branch.c:12: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'b_eq'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_branch.c:14: u8 b_eq(u8 i) {
;	-----------------------------------------
;	 function b_eq
;	-----------------------------------------
_b_eq:
	mov	r7, dpl
;	cmp_mix_branch.c:15: if ((u16)i == 3) return 1;
	cjne	r7,#0x03,00102$
	mov	dpl, #0x01
	ret
00102$:
;	cmp_mix_branch.c:16: return 0;
	mov	dpl, #0x00
;	cmp_mix_branch.c:17: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'b_ne'
;------------------------------------------------------------
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_branch.c:19: u8 b_ne(u8 i) {
;	-----------------------------------------
;	 function b_ne
;	-----------------------------------------
_b_ne:
	mov	r7, dpl
;	cmp_mix_branch.c:20: if ((u16)i != 3) return 1;
	cjne	r7,#0x03,00111$
	sjmp	00102$
00111$:
	mov	dpl, #0x01
	ret
00102$:
;	cmp_mix_branch.c:21: return 0;
	mov	dpl, #0x00
;	cmp_mix_branch.c:22: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'loop_lt'
;------------------------------------------------------------
;start         Allocated to registers 
;i             Allocated to registers r7 
;------------------------------------------------------------
;	cmp_mix_branch.c:24: u8 loop_lt(u8 start) {
;	-----------------------------------------
;	 function loop_lt
;	-----------------------------------------
_loop_lt:
	mov	r7, dpl
;	cmp_mix_branch.c:26: while ((u16)i < 8) {
00101$:
	mov	ar6,r7
	cjne	r6,#0x08,00118$
00118$:
	jnc	00103$
;	cmp_mix_branch.c:27: i = i + 1;
	mov	ar6,r7
	mov	a,r6
	inc	a
	mov	r7,a
	sjmp	00101$
00103$:
;	cmp_mix_branch.c:29: return i;
	mov	dpl, r7
;	cmp_mix_branch.c:30: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'main'
;------------------------------------------------------------
;	cmp_mix_branch.c:32: int main()
;	-----------------------------------------
;	 function main
;	-----------------------------------------
_main:
;	cmp_mix_branch.c:34: return 0;
	mov	dptr,#0x0000
;	cmp_mix_branch.c:35: }
	ret
	.area CSEG    (CODE)
	.area CONST   (CODE)
	.area XINIT   (CODE)
	.area CABS    (ABS,CODE)
