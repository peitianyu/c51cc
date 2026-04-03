                                      1 ;--------------------------------------------------------
                                      2 ; File Created by SDCC : free open source ISO C Compiler
                                      3 ; Version 4.5.0 #15242 (MINGW64)
                                      4 ;--------------------------------------------------------
                                      5 	.module cmp_mix_ops
                                      6 	
                                      7 	.optsdcc -mmcs51 --model-small
                                      8 ;--------------------------------------------------------
                                      9 ; Public variables in this module
                                     10 ;--------------------------------------------------------
                                     11 	.globl _f_sel_PARM_3
                                     12 	.globl _f_sel_PARM_2
                                     13 	.globl _main
                                     14 	.globl _f_sel
                                     15 	.globl _f_ne
                                     16 	.globl _f_eq
                                     17 	.globl _f_le
                                     18 	.globl _f_lt
                                     19 ;--------------------------------------------------------
                                     20 ; special function registers
                                     21 ;--------------------------------------------------------
                                     22 	.area RSEG    (ABS,DATA)
      000000                         23 	.org 0x0000
                                     24 ;--------------------------------------------------------
                                     25 ; special function bits
                                     26 ;--------------------------------------------------------
                                     27 	.area RSEG    (ABS,DATA)
      000000                         28 	.org 0x0000
                                     29 ;--------------------------------------------------------
                                     30 ; overlayable register banks
                                     31 ;--------------------------------------------------------
                                     32 	.area REG_BANK_0	(REL,OVR,DATA)
      000000                         33 	.ds 8
                                     34 ;--------------------------------------------------------
                                     35 ; internal ram data
                                     36 ;--------------------------------------------------------
                                     37 	.area DSEG    (DATA)
                                     38 ;--------------------------------------------------------
                                     39 ; overlayable items in internal ram
                                     40 ;--------------------------------------------------------
                                     41 	.area	OSEG    (OVR,DATA)
                                     42 	.area	OSEG    (OVR,DATA)
                                     43 	.area	OSEG    (OVR,DATA)
                                     44 	.area	OSEG    (OVR,DATA)
                                     45 	.area	OSEG    (OVR,DATA)
      000008                         46 _f_sel_PARM_2:
      000008                         47 	.ds 1
      000009                         48 _f_sel_PARM_3:
      000009                         49 	.ds 1
                                     50 ;--------------------------------------------------------
                                     51 ; Stack segment in internal ram
                                     52 ;--------------------------------------------------------
                                     53 	.area SSEG
      000021                         54 __start__stack:
      000021                         55 	.ds	1
                                     56 
                                     57 ;--------------------------------------------------------
                                     58 ; indirectly addressable internal ram data
                                     59 ;--------------------------------------------------------
                                     60 	.area ISEG    (DATA)
                                     61 ;--------------------------------------------------------
                                     62 ; absolute internal ram data
                                     63 ;--------------------------------------------------------
                                     64 	.area IABS    (ABS,DATA)
                                     65 	.area IABS    (ABS,DATA)
                                     66 ;--------------------------------------------------------
                                     67 ; bit data
                                     68 ;--------------------------------------------------------
                                     69 	.area BSEG    (BIT)
      000000                         70 _f_le_sloc0_1_0:
      000000                         71 	.ds 1
      000001                         72 _f_ne_sloc0_1_0:
      000001                         73 	.ds 1
                                     74 ;--------------------------------------------------------
                                     75 ; paged external ram data
                                     76 ;--------------------------------------------------------
                                     77 	.area PSEG    (PAG,XDATA)
                                     78 ;--------------------------------------------------------
                                     79 ; uninitialized external ram data
                                     80 ;--------------------------------------------------------
                                     81 	.area XSEG    (XDATA)
                                     82 ;--------------------------------------------------------
                                     83 ; absolute external ram data
                                     84 ;--------------------------------------------------------
                                     85 	.area XABS    (ABS,XDATA)
                                     86 ;--------------------------------------------------------
                                     87 ; initialized external ram data
                                     88 ;--------------------------------------------------------
                                     89 	.area XISEG   (XDATA)
                                     90 	.area HOME    (CODE)
                                     91 	.area GSINIT0 (CODE)
                                     92 	.area GSINIT1 (CODE)
                                     93 	.area GSINIT2 (CODE)
                                     94 	.area GSINIT3 (CODE)
                                     95 	.area GSINIT4 (CODE)
                                     96 	.area GSINIT5 (CODE)
                                     97 	.area GSINIT  (CODE)
                                     98 	.area GSFINAL (CODE)
                                     99 	.area CSEG    (CODE)
                                    100 ;--------------------------------------------------------
                                    101 ; interrupt vector
                                    102 ;--------------------------------------------------------
                                    103 	.area HOME    (CODE)
      000000                        104 __interrupt_vect:
      000000 02 00 4C         [24]  105 	ljmp	__sdcc_gsinit_startup
                                    106 ; restartable atomic support routines
      000003                        107 	.ds	5
      000008                        108 sdcc_atomic_exchange_rollback_start::
      000008 00               [12]  109 	nop
      000009 00               [12]  110 	nop
      00000A                        111 sdcc_atomic_exchange_pdata_impl:
      00000A E2               [24]  112 	movx	a, @r0
      00000B FB               [12]  113 	mov	r3, a
      00000C EA               [12]  114 	mov	a, r2
      00000D F2               [24]  115 	movx	@r0, a
      00000E 80 2C            [24]  116 	sjmp	sdcc_atomic_exchange_exit
      000010 00               [12]  117 	nop
      000011 00               [12]  118 	nop
      000012                        119 sdcc_atomic_exchange_xdata_impl:
      000012 E0               [24]  120 	movx	a, @dptr
      000013 FB               [12]  121 	mov	r3, a
      000014 EA               [12]  122 	mov	a, r2
      000015 F0               [24]  123 	movx	@dptr, a
      000016 80 24            [24]  124 	sjmp	sdcc_atomic_exchange_exit
      000018                        125 sdcc_atomic_compare_exchange_idata_impl:
      000018 E6               [12]  126 	mov	a, @r0
      000019 B5 02 02         [24]  127 	cjne	a, ar2, .+#5
      00001C EB               [12]  128 	mov	a, r3
      00001D F6               [12]  129 	mov	@r0, a
      00001E 22               [24]  130 	ret
      00001F 00               [12]  131 	nop
      000020                        132 sdcc_atomic_compare_exchange_pdata_impl:
      000020 E2               [24]  133 	movx	a, @r0
      000021 B5 02 02         [24]  134 	cjne	a, ar2, .+#5
      000024 EB               [12]  135 	mov	a, r3
      000025 F2               [24]  136 	movx	@r0, a
      000026 22               [24]  137 	ret
      000027 00               [12]  138 	nop
      000028                        139 sdcc_atomic_compare_exchange_xdata_impl:
      000028 E0               [24]  140 	movx	a, @dptr
      000029 B5 02 02         [24]  141 	cjne	a, ar2, .+#5
      00002C EB               [12]  142 	mov	a, r3
      00002D F0               [24]  143 	movx	@dptr, a
      00002E 22               [24]  144 	ret
      00002F                        145 sdcc_atomic_exchange_rollback_end::
                                    146 
      00002F                        147 sdcc_atomic_exchange_gptr_impl::
      00002F 30 F6 E0         [24]  148 	jnb	b.6, sdcc_atomic_exchange_xdata_impl
      000032 A8 82            [24]  149 	mov	r0, dpl
      000034 20 F5 D3         [24]  150 	jb	b.5, sdcc_atomic_exchange_pdata_impl
      000037                        151 sdcc_atomic_exchange_idata_impl:
      000037 EA               [12]  152 	mov	a, r2
      000038 C6               [12]  153 	xch	a, @r0
      000039 F5 82            [12]  154 	mov	dpl, a
      00003B 22               [24]  155 	ret
      00003C                        156 sdcc_atomic_exchange_exit:
      00003C 8B 82            [24]  157 	mov	dpl, r3
      00003E 22               [24]  158 	ret
      00003F                        159 sdcc_atomic_compare_exchange_gptr_impl::
      00003F 30 F6 E6         [24]  160 	jnb	b.6, sdcc_atomic_compare_exchange_xdata_impl
      000042 A8 82            [24]  161 	mov	r0, dpl
      000044 20 F5 D9         [24]  162 	jb	b.5, sdcc_atomic_compare_exchange_pdata_impl
      000047 80 CF            [24]  163 	sjmp	sdcc_atomic_compare_exchange_idata_impl
                                    164 ;--------------------------------------------------------
                                    165 ; global & static initialisations
                                    166 ;--------------------------------------------------------
                                    167 	.area HOME    (CODE)
                                    168 	.area GSINIT  (CODE)
                                    169 	.area GSFINAL (CODE)
                                    170 	.area GSINIT  (CODE)
                                    171 	.globl __sdcc_gsinit_startup
                                    172 	.globl __sdcc_program_startup
                                    173 	.globl __start__stack
                                    174 	.globl __mcs51_genXINIT
                                    175 	.globl __mcs51_genXRAMCLEAR
                                    176 	.globl __mcs51_genRAMCLEAR
                                    177 	.area GSFINAL (CODE)
      0000A5 02 00 49         [24]  178 	ljmp	__sdcc_program_startup
                                    179 ;--------------------------------------------------------
                                    180 ; Home
                                    181 ;--------------------------------------------------------
                                    182 	.area HOME    (CODE)
                                    183 	.area HOME    (CODE)
      000049                        184 __sdcc_program_startup:
      000049 02 00 EA         [24]  185 	ljmp	_main
                                    186 ;	return from main will return to caller
                                    187 ;--------------------------------------------------------
                                    188 ; code
                                    189 ;--------------------------------------------------------
                                    190 	.area CSEG    (CODE)
                                    191 ;------------------------------------------------------------
                                    192 ;Allocation info for local variables in function 'f_lt'
                                    193 ;------------------------------------------------------------
                                    194 ;i             Allocated to registers r7 
                                    195 ;------------------------------------------------------------
                                    196 ;	cmp_mix_ops.c:4: u8 f_lt(u8 i) { return i < 8; }
                                    197 ;	-----------------------------------------
                                    198 ;	 function f_lt
                                    199 ;	-----------------------------------------
      0000A8                        200 _f_lt:
                           000007   201 	ar7 = 0x07
                           000006   202 	ar6 = 0x06
                           000005   203 	ar5 = 0x05
                           000004   204 	ar4 = 0x04
                           000003   205 	ar3 = 0x03
                           000002   206 	ar2 = 0x02
                           000001   207 	ar1 = 0x01
                           000000   208 	ar0 = 0x00
      0000A8 AF 82            [24]  209 	mov	r7, dpl
      0000AA BF 08 00         [24]  210 	cjne	r7,#0x08,00103$
      0000AD                        211 00103$:
      0000AD E4               [12]  212 	clr	a
      0000AE 33               [12]  213 	rlc	a
      0000AF F5 82            [12]  214 	mov	dpl,a
      0000B1 22               [24]  215 	ret
                                    216 ;------------------------------------------------------------
                                    217 ;Allocation info for local variables in function 'f_le'
                                    218 ;------------------------------------------------------------
                                    219 ;i             Allocated to registers r7 
                                    220 ;------------------------------------------------------------
                                    221 ;	cmp_mix_ops.c:5: u8 f_le(u8 i) { return i <= 8; }
                                    222 ;	-----------------------------------------
                                    223 ;	 function f_le
                                    224 ;	-----------------------------------------
      0000B2                        225 _f_le:
      0000B2 E5 82            [12]  226 	mov	a,dpl
      0000B4 24 F7            [12]  227 	add	a,#0xff - 0x08
      0000B6 B3               [12]  228 	cpl	c
      0000B7 92 00            [24]  229 	mov	_f_le_sloc0_1_0,c
      0000B9 E4               [12]  230 	clr	a
      0000BA 33               [12]  231 	rlc	a
      0000BB F5 82            [12]  232 	mov	dpl,a
      0000BD 22               [24]  233 	ret
                                    234 ;------------------------------------------------------------
                                    235 ;Allocation info for local variables in function 'f_eq'
                                    236 ;------------------------------------------------------------
                                    237 ;i             Allocated to registers r7 
                                    238 ;------------------------------------------------------------
                                    239 ;	cmp_mix_ops.c:6: u8 f_eq(u8 i) { return i == 3; }
                                    240 ;	-----------------------------------------
                                    241 ;	 function f_eq
                                    242 ;	-----------------------------------------
      0000BE                        243 _f_eq:
      0000BE AF 82            [24]  244 	mov	r7, dpl
      0000C0 E4               [12]  245 	clr	a
      0000C1 BF 03 01         [24]  246 	cjne	r7,#0x03,00103$
      0000C4 04               [12]  247 	inc	a
      0000C5                        248 00103$:
      0000C5 F5 82            [12]  249 	mov	dpl,a
      0000C7 22               [24]  250 	ret
                                    251 ;------------------------------------------------------------
                                    252 ;Allocation info for local variables in function 'f_ne'
                                    253 ;------------------------------------------------------------
                                    254 ;i             Allocated to registers r7 
                                    255 ;------------------------------------------------------------
                                    256 ;	cmp_mix_ops.c:7: u8 f_ne(u8 i) { return i != 3; }
                                    257 ;	-----------------------------------------
                                    258 ;	 function f_ne
                                    259 ;	-----------------------------------------
      0000C8                        260 _f_ne:
      0000C8 AF 82            [24]  261 	mov	r7, dpl
      0000CA BF 03 03         [24]  262 	cjne	r7,#0x03,00103$
      0000CD D3               [12]  263 	setb	c
      0000CE 80 01            [24]  264 	sjmp	00104$
      0000D0                        265 00103$:
      0000D0 C3               [12]  266 	clr	c
      0000D1                        267 00104$:
      0000D1 B3               [12]  268 	cpl	c
      0000D2 92 01            [24]  269 	mov	_f_ne_sloc0_1_0,c
      0000D4 E4               [12]  270 	clr	a
      0000D5 33               [12]  271 	rlc	a
      0000D6 F5 82            [12]  272 	mov	dpl,a
      0000D8 22               [24]  273 	ret
                                    274 ;------------------------------------------------------------
                                    275 ;Allocation info for local variables in function 'f_sel'
                                    276 ;------------------------------------------------------------
                                    277 ;a             Allocated with name '_f_sel_PARM_2'
                                    278 ;b             Allocated with name '_f_sel_PARM_3'
                                    279 ;c             Allocated to registers r7 
                                    280 ;------------------------------------------------------------
                                    281 ;	cmp_mix_ops.c:9: u16 f_sel(u8 c, u8 a, u8 b) {
                                    282 ;	-----------------------------------------
                                    283 ;	 function f_sel
                                    284 ;	-----------------------------------------
      0000D9                        285 _f_sel:
                                    286 ;	cmp_mix_ops.c:10: return c ? a : b;
      0000D9 E5 82            [12]  287 	mov	a,dpl
      0000DB 60 04            [24]  288 	jz	00103$
      0000DD AF 08            [24]  289 	mov	r7,_f_sel_PARM_2
      0000DF 80 02            [24]  290 	sjmp	00104$
      0000E1                        291 00103$:
      0000E1 AF 09            [24]  292 	mov	r7,_f_sel_PARM_3
      0000E3                        293 00104$:
      0000E3 7E 00            [12]  294 	mov	r6,#0x00
      0000E5 8F 82            [24]  295 	mov	dpl, r7
      0000E7 8E 83            [24]  296 	mov	dph, r6
                                    297 ;	cmp_mix_ops.c:11: }
      0000E9 22               [24]  298 	ret
                                    299 ;------------------------------------------------------------
                                    300 ;Allocation info for local variables in function 'main'
                                    301 ;------------------------------------------------------------
                                    302 ;	cmp_mix_ops.c:13: int main()
                                    303 ;	-----------------------------------------
                                    304 ;	 function main
                                    305 ;	-----------------------------------------
      0000EA                        306 _main:
                                    307 ;	cmp_mix_ops.c:15: return 0;
      0000EA 90 00 00         [24]  308 	mov	dptr,#0x0000
                                    309 ;	cmp_mix_ops.c:16: }
      0000ED 22               [24]  310 	ret
                                    311 	.area CSEG    (CODE)
                                    312 	.area CONST   (CODE)
                                    313 	.area XINIT   (CODE)
                                    314 	.area CABS    (ABS,CODE)
