                                      1 ;--------------------------------------------------------
                                      2 ; File Created by SDCC : free open source ISO C Compiler
                                      3 ; Version 4.5.0 #15242 (MINGW64)
                                      4 ;--------------------------------------------------------
                                      5 	.module arith_ext_int
                                      6 	
                                      7 	.optsdcc -mmcs51 --model-small
                                      8 ;--------------------------------------------------------
                                      9 ; Public variables in this module
                                     10 ;--------------------------------------------------------
                                     11 	.globl _mixed_unsigned_signed_PARM_2
                                     12 	.globl _mixed_signed_unsigned_PARM_2
                                     13 	.globl _shr_unsigned_PARM_2
                                     14 	.globl _shr_signed_PARM_2
                                     15 	.globl _shl_int_PARM_2
                                     16 	.globl _sub_borrow_unsigned_PARM_2
                                     17 	.globl _sub_borrow_signed_PARM_2
                                     18 	.globl _add_overflow_unsigned_PARM_2
                                     19 	.globl _add_overflow_signed_PARM_2
                                     20 	.globl _main
                                     21 	.globl _sub_min_max
                                     22 	.globl _add_min_max
                                     23 	.globl _mixed_unsigned_signed
                                     24 	.globl _mixed_signed_unsigned
                                     25 	.globl _shr_unsigned
                                     26 	.globl _shr_signed
                                     27 	.globl _shl_int
                                     28 	.globl _mod_unsigned
                                     29 	.globl _div_unsigned
                                     30 	.globl _mod_signed
                                     31 	.globl _div_signed
                                     32 	.globl _mul_unsigned
                                     33 	.globl _mul_signed
                                     34 	.globl _sub_borrow_unsigned
                                     35 	.globl _sub_borrow_signed
                                     36 	.globl _addu_with_const
                                     37 	.globl _add_with_const
                                     38 	.globl _add_overflow_unsigned
                                     39 	.globl _add_overflow_signed
                                     40 	.globl _mod_unsigned_PARM_2
                                     41 	.globl _div_unsigned_PARM_2
                                     42 	.globl _mod_signed_PARM_2
                                     43 	.globl _div_signed_PARM_2
                                     44 	.globl _mul_unsigned_PARM_2
                                     45 	.globl _mul_signed_PARM_2
                                     46 ;--------------------------------------------------------
                                     47 ; special function registers
                                     48 ;--------------------------------------------------------
                                     49 	.area RSEG    (ABS,DATA)
      000000                         50 	.org 0x0000
                                     51 ;--------------------------------------------------------
                                     52 ; special function bits
                                     53 ;--------------------------------------------------------
                                     54 	.area RSEG    (ABS,DATA)
      000000                         55 	.org 0x0000
                                     56 ;--------------------------------------------------------
                                     57 ; overlayable register banks
                                     58 ;--------------------------------------------------------
                                     59 	.area REG_BANK_0	(REL,OVR,DATA)
      000000                         60 	.ds 8
                                     61 ;--------------------------------------------------------
                                     62 ; internal ram data
                                     63 ;--------------------------------------------------------
                                     64 	.area DSEG    (DATA)
      000008                         65 _mul_signed_PARM_2:
      000008                         66 	.ds 2
      00000A                         67 _mul_unsigned_PARM_2:
      00000A                         68 	.ds 2
      00000C                         69 _div_signed_PARM_2:
      00000C                         70 	.ds 2
      00000E                         71 _mod_signed_PARM_2:
      00000E                         72 	.ds 2
      000010                         73 _div_unsigned_PARM_2:
      000010                         74 	.ds 2
      000012                         75 _mod_unsigned_PARM_2:
      000012                         76 	.ds 2
                                     77 ;--------------------------------------------------------
                                     78 ; overlayable items in internal ram
                                     79 ;--------------------------------------------------------
                                     80 	.area	OSEG    (OVR,DATA)
      000014                         81 _add_overflow_signed_PARM_2:
      000014                         82 	.ds 2
                                     83 	.area	OSEG    (OVR,DATA)
      000014                         84 _add_overflow_unsigned_PARM_2:
      000014                         85 	.ds 2
                                     86 	.area	OSEG    (OVR,DATA)
                                     87 	.area	OSEG    (OVR,DATA)
                                     88 	.area	OSEG    (OVR,DATA)
      000014                         89 _sub_borrow_signed_PARM_2:
      000014                         90 	.ds 2
                                     91 	.area	OSEG    (OVR,DATA)
      000014                         92 _sub_borrow_unsigned_PARM_2:
      000014                         93 	.ds 2
                                     94 	.area	OSEG    (OVR,DATA)
      000014                         95 _shl_int_PARM_2:
      000014                         96 	.ds 2
                                     97 	.area	OSEG    (OVR,DATA)
      000014                         98 _shr_signed_PARM_2:
      000014                         99 	.ds 2
                                    100 	.area	OSEG    (OVR,DATA)
      000014                        101 _shr_unsigned_PARM_2:
      000014                        102 	.ds 2
                                    103 	.area	OSEG    (OVR,DATA)
      000014                        104 _mixed_signed_unsigned_PARM_2:
      000014                        105 	.ds 2
                                    106 	.area	OSEG    (OVR,DATA)
      000014                        107 _mixed_unsigned_signed_PARM_2:
      000014                        108 	.ds 2
                                    109 ;--------------------------------------------------------
                                    110 ; Stack segment in internal ram
                                    111 ;--------------------------------------------------------
                                    112 	.area SSEG
      000016                        113 __start__stack:
      000016                        114 	.ds	1
                                    115 
                                    116 ;--------------------------------------------------------
                                    117 ; indirectly addressable internal ram data
                                    118 ;--------------------------------------------------------
                                    119 	.area ISEG    (DATA)
                                    120 ;--------------------------------------------------------
                                    121 ; absolute internal ram data
                                    122 ;--------------------------------------------------------
                                    123 	.area IABS    (ABS,DATA)
                                    124 	.area IABS    (ABS,DATA)
                                    125 ;--------------------------------------------------------
                                    126 ; bit data
                                    127 ;--------------------------------------------------------
                                    128 	.area BSEG    (BIT)
                                    129 ;--------------------------------------------------------
                                    130 ; paged external ram data
                                    131 ;--------------------------------------------------------
                                    132 	.area PSEG    (PAG,XDATA)
                                    133 ;--------------------------------------------------------
                                    134 ; uninitialized external ram data
                                    135 ;--------------------------------------------------------
                                    136 	.area XSEG    (XDATA)
                                    137 ;--------------------------------------------------------
                                    138 ; absolute external ram data
                                    139 ;--------------------------------------------------------
                                    140 	.area XABS    (ABS,XDATA)
                                    141 ;--------------------------------------------------------
                                    142 ; initialized external ram data
                                    143 ;--------------------------------------------------------
                                    144 	.area XISEG   (XDATA)
                                    145 	.area HOME    (CODE)
                                    146 	.area GSINIT0 (CODE)
                                    147 	.area GSINIT1 (CODE)
                                    148 	.area GSINIT2 (CODE)
                                    149 	.area GSINIT3 (CODE)
                                    150 	.area GSINIT4 (CODE)
                                    151 	.area GSINIT5 (CODE)
                                    152 	.area GSINIT  (CODE)
                                    153 	.area GSFINAL (CODE)
                                    154 	.area CSEG    (CODE)
                                    155 ;--------------------------------------------------------
                                    156 ; interrupt vector
                                    157 ;--------------------------------------------------------
                                    158 	.area HOME    (CODE)
      000000                        159 __interrupt_vect:
      000000 02 00 4C         [24]  160 	ljmp	__sdcc_gsinit_startup
                                    161 ; restartable atomic support routines
      000003                        162 	.ds	5
      000008                        163 sdcc_atomic_exchange_rollback_start::
      000008 00               [12]  164 	nop
      000009 00               [12]  165 	nop
      00000A                        166 sdcc_atomic_exchange_pdata_impl:
      00000A E2               [24]  167 	movx	a, @r0
      00000B FB               [12]  168 	mov	r3, a
      00000C EA               [12]  169 	mov	a, r2
      00000D F2               [24]  170 	movx	@r0, a
      00000E 80 2C            [24]  171 	sjmp	sdcc_atomic_exchange_exit
      000010 00               [12]  172 	nop
      000011 00               [12]  173 	nop
      000012                        174 sdcc_atomic_exchange_xdata_impl:
      000012 E0               [24]  175 	movx	a, @dptr
      000013 FB               [12]  176 	mov	r3, a
      000014 EA               [12]  177 	mov	a, r2
      000015 F0               [24]  178 	movx	@dptr, a
      000016 80 24            [24]  179 	sjmp	sdcc_atomic_exchange_exit
      000018                        180 sdcc_atomic_compare_exchange_idata_impl:
      000018 E6               [12]  181 	mov	a, @r0
      000019 B5 02 02         [24]  182 	cjne	a, ar2, .+#5
      00001C EB               [12]  183 	mov	a, r3
      00001D F6               [12]  184 	mov	@r0, a
      00001E 22               [24]  185 	ret
      00001F 00               [12]  186 	nop
      000020                        187 sdcc_atomic_compare_exchange_pdata_impl:
      000020 E2               [24]  188 	movx	a, @r0
      000021 B5 02 02         [24]  189 	cjne	a, ar2, .+#5
      000024 EB               [12]  190 	mov	a, r3
      000025 F2               [24]  191 	movx	@r0, a
      000026 22               [24]  192 	ret
      000027 00               [12]  193 	nop
      000028                        194 sdcc_atomic_compare_exchange_xdata_impl:
      000028 E0               [24]  195 	movx	a, @dptr
      000029 B5 02 02         [24]  196 	cjne	a, ar2, .+#5
      00002C EB               [12]  197 	mov	a, r3
      00002D F0               [24]  198 	movx	@dptr, a
      00002E 22               [24]  199 	ret
      00002F                        200 sdcc_atomic_exchange_rollback_end::
                                    201 
      00002F                        202 sdcc_atomic_exchange_gptr_impl::
      00002F 30 F6 E0         [24]  203 	jnb	b.6, sdcc_atomic_exchange_xdata_impl
      000032 A8 82            [24]  204 	mov	r0, dpl
      000034 20 F5 D3         [24]  205 	jb	b.5, sdcc_atomic_exchange_pdata_impl
      000037                        206 sdcc_atomic_exchange_idata_impl:
      000037 EA               [12]  207 	mov	a, r2
      000038 C6               [12]  208 	xch	a, @r0
      000039 F5 82            [12]  209 	mov	dpl, a
      00003B 22               [24]  210 	ret
      00003C                        211 sdcc_atomic_exchange_exit:
      00003C 8B 82            [24]  212 	mov	dpl, r3
      00003E 22               [24]  213 	ret
      00003F                        214 sdcc_atomic_compare_exchange_gptr_impl::
      00003F 30 F6 E6         [24]  215 	jnb	b.6, sdcc_atomic_compare_exchange_xdata_impl
      000042 A8 82            [24]  216 	mov	r0, dpl
      000044 20 F5 D9         [24]  217 	jb	b.5, sdcc_atomic_compare_exchange_pdata_impl
      000047 80 CF            [24]  218 	sjmp	sdcc_atomic_compare_exchange_idata_impl
                                    219 ;--------------------------------------------------------
                                    220 ; global & static initialisations
                                    221 ;--------------------------------------------------------
                                    222 	.area HOME    (CODE)
                                    223 	.area GSINIT  (CODE)
                                    224 	.area GSFINAL (CODE)
                                    225 	.area GSINIT  (CODE)
                                    226 	.globl __sdcc_gsinit_startup
                                    227 	.globl __sdcc_program_startup
                                    228 	.globl __start__stack
                                    229 	.globl __mcs51_genXINIT
                                    230 	.globl __mcs51_genXRAMCLEAR
                                    231 	.globl __mcs51_genRAMCLEAR
                                    232 	.area GSFINAL (CODE)
      0000A5 02 00 49         [24]  233 	ljmp	__sdcc_program_startup
                                    234 ;--------------------------------------------------------
                                    235 ; Home
                                    236 ;--------------------------------------------------------
                                    237 	.area HOME    (CODE)
                                    238 	.area HOME    (CODE)
      000049                        239 __sdcc_program_startup:
      000049 02 01 C7         [24]  240 	ljmp	_main
                                    241 ;	return from main will return to caller
                                    242 ;--------------------------------------------------------
                                    243 ; code
                                    244 ;--------------------------------------------------------
                                    245 	.area CSEG    (CODE)
                                    246 ;------------------------------------------------------------
                                    247 ;Allocation info for local variables in function 'add_overflow_signed'
                                    248 ;------------------------------------------------------------
                                    249 ;b             Allocated with name '_add_overflow_signed_PARM_2'
                                    250 ;a             Allocated to registers r6 r7 
                                    251 ;------------------------------------------------------------
                                    252 ;	arith_ext_int.c:1: int add_overflow_signed(int a,int b){ return a + b; }
                                    253 ;	-----------------------------------------
                                    254 ;	 function add_overflow_signed
                                    255 ;	-----------------------------------------
      0000A8                        256 _add_overflow_signed:
                           000007   257 	ar7 = 0x07
                           000006   258 	ar6 = 0x06
                           000005   259 	ar5 = 0x05
                           000004   260 	ar4 = 0x04
                           000003   261 	ar3 = 0x03
                           000002   262 	ar2 = 0x02
                           000001   263 	ar1 = 0x01
                           000000   264 	ar0 = 0x00
      0000A8 AE 82            [24]  265 	mov	r6, dpl
      0000AA AF 83            [24]  266 	mov	r7, dph
      0000AC E5 14            [12]  267 	mov	a,_add_overflow_signed_PARM_2
      0000AE 2E               [12]  268 	add	a, r6
      0000AF F5 82            [12]  269 	mov	dpl,a
      0000B1 E5 15            [12]  270 	mov	a,(_add_overflow_signed_PARM_2 + 1)
      0000B3 3F               [12]  271 	addc	a, r7
      0000B4 F5 83            [12]  272 	mov	dph,a
      0000B6 22               [24]  273 	ret
                                    274 ;------------------------------------------------------------
                                    275 ;Allocation info for local variables in function 'add_overflow_unsigned'
                                    276 ;------------------------------------------------------------
                                    277 ;b             Allocated with name '_add_overflow_unsigned_PARM_2'
                                    278 ;a             Allocated to registers r6 r7 
                                    279 ;------------------------------------------------------------
                                    280 ;	arith_ext_int.c:2: unsigned int add_overflow_unsigned(unsigned int a,unsigned int b){ return a + b; }
                                    281 ;	-----------------------------------------
                                    282 ;	 function add_overflow_unsigned
                                    283 ;	-----------------------------------------
      0000B7                        284 _add_overflow_unsigned:
      0000B7 AE 82            [24]  285 	mov	r6, dpl
      0000B9 AF 83            [24]  286 	mov	r7, dph
      0000BB E5 14            [12]  287 	mov	a,_add_overflow_unsigned_PARM_2
      0000BD 2E               [12]  288 	add	a, r6
      0000BE F5 82            [12]  289 	mov	dpl,a
      0000C0 E5 15            [12]  290 	mov	a,(_add_overflow_unsigned_PARM_2 + 1)
      0000C2 3F               [12]  291 	addc	a, r7
      0000C3 F5 83            [12]  292 	mov	dph,a
      0000C5 22               [24]  293 	ret
                                    294 ;------------------------------------------------------------
                                    295 ;Allocation info for local variables in function 'add_with_const'
                                    296 ;------------------------------------------------------------
                                    297 ;a             Allocated to registers r6 r7 
                                    298 ;------------------------------------------------------------
                                    299 ;	arith_ext_int.c:4: int add_with_const(int a){ return a + 32767; }
                                    300 ;	-----------------------------------------
                                    301 ;	 function add_with_const
                                    302 ;	-----------------------------------------
      0000C6                        303 _add_with_const:
      0000C6 AE 82            [24]  304 	mov	r6, dpl
      0000C8 AF 83            [24]  305 	mov	r7, dph
      0000CA 74 FF            [12]  306 	mov	a,#0xff
      0000CC 2E               [12]  307 	add	a, r6
      0000CD F5 82            [12]  308 	mov	dpl,a
      0000CF 74 7F            [12]  309 	mov	a,#0x7f
      0000D1 3F               [12]  310 	addc	a, r7
      0000D2 F5 83            [12]  311 	mov	dph,a
      0000D4 22               [24]  312 	ret
                                    313 ;------------------------------------------------------------
                                    314 ;Allocation info for local variables in function 'addu_with_const'
                                    315 ;------------------------------------------------------------
                                    316 ;a             Allocated to registers r6 r7 
                                    317 ;------------------------------------------------------------
                                    318 ;	arith_ext_int.c:5: unsigned int addu_with_const(unsigned int a){ return a + (unsigned int)65535; }
                                    319 ;	-----------------------------------------
                                    320 ;	 function addu_with_const
                                    321 ;	-----------------------------------------
      0000D5                        322 _addu_with_const:
      0000D5 AE 82            [24]  323 	mov	r6, dpl
      0000D7 AF 83            [24]  324 	mov	r7, dph
      0000D9 74 FF            [12]  325 	mov	a,#0xff
      0000DB 2E               [12]  326 	add	a, r6
      0000DC F5 82            [12]  327 	mov	dpl,a
      0000DE 74 FF            [12]  328 	mov	a,#0xff
      0000E0 3F               [12]  329 	addc	a, r7
      0000E1 F5 83            [12]  330 	mov	dph,a
      0000E3 22               [24]  331 	ret
                                    332 ;------------------------------------------------------------
                                    333 ;Allocation info for local variables in function 'sub_borrow_signed'
                                    334 ;------------------------------------------------------------
                                    335 ;b             Allocated with name '_sub_borrow_signed_PARM_2'
                                    336 ;a             Allocated to registers r6 r7 
                                    337 ;------------------------------------------------------------
                                    338 ;	arith_ext_int.c:7: int sub_borrow_signed(int a,int b){ return a - b; }
                                    339 ;	-----------------------------------------
                                    340 ;	 function sub_borrow_signed
                                    341 ;	-----------------------------------------
      0000E4                        342 _sub_borrow_signed:
      0000E4 AE 82            [24]  343 	mov	r6, dpl
      0000E6 AF 83            [24]  344 	mov	r7, dph
      0000E8 EE               [12]  345 	mov	a,r6
      0000E9 C3               [12]  346 	clr	c
      0000EA 95 14            [12]  347 	subb	a,_sub_borrow_signed_PARM_2
      0000EC F5 82            [12]  348 	mov	dpl,a
      0000EE EF               [12]  349 	mov	a,r7
      0000EF 95 15            [12]  350 	subb	a,(_sub_borrow_signed_PARM_2 + 1)
      0000F1 F5 83            [12]  351 	mov	dph,a
      0000F3 22               [24]  352 	ret
                                    353 ;------------------------------------------------------------
                                    354 ;Allocation info for local variables in function 'sub_borrow_unsigned'
                                    355 ;------------------------------------------------------------
                                    356 ;b             Allocated with name '_sub_borrow_unsigned_PARM_2'
                                    357 ;a             Allocated to registers r6 r7 
                                    358 ;------------------------------------------------------------
                                    359 ;	arith_ext_int.c:8: unsigned int sub_borrow_unsigned(unsigned int a,unsigned int b){ return a - b; }
                                    360 ;	-----------------------------------------
                                    361 ;	 function sub_borrow_unsigned
                                    362 ;	-----------------------------------------
      0000F4                        363 _sub_borrow_unsigned:
      0000F4 AE 82            [24]  364 	mov	r6, dpl
      0000F6 AF 83            [24]  365 	mov	r7, dph
      0000F8 EE               [12]  366 	mov	a,r6
      0000F9 C3               [12]  367 	clr	c
      0000FA 95 14            [12]  368 	subb	a,_sub_borrow_unsigned_PARM_2
      0000FC F5 82            [12]  369 	mov	dpl,a
      0000FE EF               [12]  370 	mov	a,r7
      0000FF 95 15            [12]  371 	subb	a,(_sub_borrow_unsigned_PARM_2 + 1)
      000101 F5 83            [12]  372 	mov	dph,a
      000103 22               [24]  373 	ret
                                    374 ;------------------------------------------------------------
                                    375 ;Allocation info for local variables in function 'mul_signed'
                                    376 ;------------------------------------------------------------
                                    377 ;b             Allocated with name '_mul_signed_PARM_2'
                                    378 ;a             Allocated to registers r6 r7 
                                    379 ;------------------------------------------------------------
                                    380 ;	arith_ext_int.c:10: int mul_signed(int a,int b){ return a * b; }
                                    381 ;	-----------------------------------------
                                    382 ;	 function mul_signed
                                    383 ;	-----------------------------------------
      000104                        384 _mul_signed:
      000104 85 08 14         [24]  385 	mov	__mulint_PARM_2,_mul_signed_PARM_2
      000107 85 09 15         [24]  386 	mov	(__mulint_PARM_2 + 1),(_mul_signed_PARM_2 + 1)
      00010A 02 01 F4         [24]  387 	ljmp	__mulint
                                    388 ;------------------------------------------------------------
                                    389 ;Allocation info for local variables in function 'mul_unsigned'
                                    390 ;------------------------------------------------------------
                                    391 ;b             Allocated with name '_mul_unsigned_PARM_2'
                                    392 ;a             Allocated to registers r6 r7 
                                    393 ;------------------------------------------------------------
                                    394 ;	arith_ext_int.c:11: unsigned int mul_unsigned(unsigned int a,unsigned int b){ return a * b; }
                                    395 ;	-----------------------------------------
                                    396 ;	 function mul_unsigned
                                    397 ;	-----------------------------------------
      00010D                        398 _mul_unsigned:
      00010D 85 0A 14         [24]  399 	mov	__mulint_PARM_2,_mul_unsigned_PARM_2
      000110 85 0B 15         [24]  400 	mov	(__mulint_PARM_2 + 1),(_mul_unsigned_PARM_2 + 1)
      000113 02 01 F4         [24]  401 	ljmp	__mulint
                                    402 ;------------------------------------------------------------
                                    403 ;Allocation info for local variables in function 'div_signed'
                                    404 ;------------------------------------------------------------
                                    405 ;b             Allocated with name '_div_signed_PARM_2'
                                    406 ;a             Allocated to registers r6 r7 
                                    407 ;------------------------------------------------------------
                                    408 ;	arith_ext_int.c:13: int div_signed(int a,int b){ return a / b; }
                                    409 ;	-----------------------------------------
                                    410 ;	 function div_signed
                                    411 ;	-----------------------------------------
      000116                        412 _div_signed:
      000116 85 0C 14         [24]  413 	mov	__divsint_PARM_2,_div_signed_PARM_2
      000119 85 0D 15         [24]  414 	mov	(__divsint_PARM_2 + 1),(_div_signed_PARM_2 + 1)
      00011C 02 02 94         [24]  415 	ljmp	__divsint
                                    416 ;------------------------------------------------------------
                                    417 ;Allocation info for local variables in function 'mod_signed'
                                    418 ;------------------------------------------------------------
                                    419 ;b             Allocated with name '_mod_signed_PARM_2'
                                    420 ;a             Allocated to registers r6 r7 
                                    421 ;------------------------------------------------------------
                                    422 ;	arith_ext_int.c:14: int mod_signed(int a,int b){ return a % b; }
                                    423 ;	-----------------------------------------
                                    424 ;	 function mod_signed
                                    425 ;	-----------------------------------------
      00011F                        426 _mod_signed:
      00011F 85 0E 14         [24]  427 	mov	__modsint_PARM_2,_mod_signed_PARM_2
      000122 85 0F 15         [24]  428 	mov	(__modsint_PARM_2 + 1),(_mod_signed_PARM_2 + 1)
      000125 02 02 5E         [24]  429 	ljmp	__modsint
                                    430 ;------------------------------------------------------------
                                    431 ;Allocation info for local variables in function 'div_unsigned'
                                    432 ;------------------------------------------------------------
                                    433 ;b             Allocated with name '_div_unsigned_PARM_2'
                                    434 ;a             Allocated to registers r6 r7 
                                    435 ;------------------------------------------------------------
                                    436 ;	arith_ext_int.c:15: unsigned int div_unsigned(unsigned int a,unsigned int b){ return a / b; }
                                    437 ;	-----------------------------------------
                                    438 ;	 function div_unsigned
                                    439 ;	-----------------------------------------
      000128                        440 _div_unsigned:
      000128 85 10 14         [24]  441 	mov	__divuint_PARM_2,_div_unsigned_PARM_2
      00012B 85 11 15         [24]  442 	mov	(__divuint_PARM_2 + 1),(_div_unsigned_PARM_2 + 1)
      00012E 02 01 CB         [24]  443 	ljmp	__divuint
                                    444 ;------------------------------------------------------------
                                    445 ;Allocation info for local variables in function 'mod_unsigned'
                                    446 ;------------------------------------------------------------
                                    447 ;b             Allocated with name '_mod_unsigned_PARM_2'
                                    448 ;a             Allocated to registers r6 r7 
                                    449 ;------------------------------------------------------------
                                    450 ;	arith_ext_int.c:16: unsigned int mod_unsigned(unsigned int a,unsigned int b){ return a % b; }
                                    451 ;	-----------------------------------------
                                    452 ;	 function mod_unsigned
                                    453 ;	-----------------------------------------
      000131                        454 _mod_unsigned:
      000131 85 12 14         [24]  455 	mov	__moduint_PARM_2,_mod_unsigned_PARM_2
      000134 85 13 15         [24]  456 	mov	(__moduint_PARM_2 + 1),(_mod_unsigned_PARM_2 + 1)
      000137 02 02 11         [24]  457 	ljmp	__moduint
                                    458 ;------------------------------------------------------------
                                    459 ;Allocation info for local variables in function 'shl_int'
                                    460 ;------------------------------------------------------------
                                    461 ;c             Allocated with name '_shl_int_PARM_2'
                                    462 ;a             Allocated to registers r6 r7 
                                    463 ;------------------------------------------------------------
                                    464 ;	arith_ext_int.c:18: int shl_int(int a,int c){ return a << c; }
                                    465 ;	-----------------------------------------
                                    466 ;	 function shl_int
                                    467 ;	-----------------------------------------
      00013A                        468 _shl_int:
      00013A AE 82            [24]  469 	mov	r6, dpl
      00013C AF 83            [24]  470 	mov	r7, dph
      00013E 85 14 F0         [24]  471 	mov	b,_shl_int_PARM_2
      000141 05 F0            [12]  472 	inc	b
      000143 85 06 82         [24]  473 	mov	dpl,ar6
      000146 85 07 83         [24]  474 	mov	dph,ar7
      000149 80 0B            [24]  475 	sjmp	00104$
      00014B                        476 00103$:
      00014B E5 82            [12]  477 	mov	a,dpl
      00014D 25 82            [12]  478 	add	a,dpl
      00014F F5 82            [12]  479 	mov	dpl,a
      000151 E5 83            [12]  480 	mov	a,dph
      000153 33               [12]  481 	rlc	a
      000154 F5 83            [12]  482 	mov	dph,a
      000156                        483 00104$:
      000156 D5 F0 F2         [24]  484 	djnz	b,00103$
      000159 22               [24]  485 	ret
                                    486 ;------------------------------------------------------------
                                    487 ;Allocation info for local variables in function 'shr_signed'
                                    488 ;------------------------------------------------------------
                                    489 ;c             Allocated with name '_shr_signed_PARM_2'
                                    490 ;a             Allocated to registers r6 r7 
                                    491 ;------------------------------------------------------------
                                    492 ;	arith_ext_int.c:19: int shr_signed(int a,int c){ return a >> c; }
                                    493 ;	-----------------------------------------
                                    494 ;	 function shr_signed
                                    495 ;	-----------------------------------------
      00015A                        496 _shr_signed:
      00015A AE 82            [24]  497 	mov	r6, dpl
      00015C AF 83            [24]  498 	mov	r7, dph
      00015E 85 14 F0         [24]  499 	mov	b,_shr_signed_PARM_2
      000161 05 F0            [12]  500 	inc	b
      000163 85 06 82         [24]  501 	mov	dpl,ar6
      000166 85 07 83         [24]  502 	mov	dph,ar7
      000169 EF               [12]  503 	mov	a,r7
      00016A 33               [12]  504 	rlc	a
      00016B 92 D2            [24]  505 	mov	ov,c
      00016D 80 0C            [24]  506 	sjmp	00104$
      00016F                        507 00103$:
      00016F A2 D2            [12]  508 	mov	c,ov
      000171 E5 83            [12]  509 	mov	a,dph
      000173 13               [12]  510 	rrc	a
      000174 F5 83            [12]  511 	mov	dph,a
      000176 E5 82            [12]  512 	mov	a,dpl
      000178 13               [12]  513 	rrc	a
      000179 F5 82            [12]  514 	mov	dpl,a
      00017B                        515 00104$:
      00017B D5 F0 F1         [24]  516 	djnz	b,00103$
      00017E 22               [24]  517 	ret
                                    518 ;------------------------------------------------------------
                                    519 ;Allocation info for local variables in function 'shr_unsigned'
                                    520 ;------------------------------------------------------------
                                    521 ;c             Allocated with name '_shr_unsigned_PARM_2'
                                    522 ;a             Allocated to registers r6 r7 
                                    523 ;------------------------------------------------------------
                                    524 ;	arith_ext_int.c:20: unsigned int shr_unsigned(unsigned int a,int c){ return a >> c; }
                                    525 ;	-----------------------------------------
                                    526 ;	 function shr_unsigned
                                    527 ;	-----------------------------------------
      00017F                        528 _shr_unsigned:
      00017F AE 82            [24]  529 	mov	r6, dpl
      000181 AF 83            [24]  530 	mov	r7, dph
      000183 85 14 F0         [24]  531 	mov	b,_shr_unsigned_PARM_2
      000186 05 F0            [12]  532 	inc	b
      000188 85 06 82         [24]  533 	mov	dpl,ar6
      00018B 85 07 83         [24]  534 	mov	dph,ar7
      00018E 80 0B            [24]  535 	sjmp	00104$
      000190                        536 00103$:
      000190 C3               [12]  537 	clr	c
      000191 E5 83            [12]  538 	mov	a,dph
      000193 13               [12]  539 	rrc	a
      000194 F5 83            [12]  540 	mov	dph,a
      000196 E5 82            [12]  541 	mov	a,dpl
      000198 13               [12]  542 	rrc	a
      000199 F5 82            [12]  543 	mov	dpl,a
      00019B                        544 00104$:
      00019B D5 F0 F2         [24]  545 	djnz	b,00103$
      00019E 22               [24]  546 	ret
                                    547 ;------------------------------------------------------------
                                    548 ;Allocation info for local variables in function 'mixed_signed_unsigned'
                                    549 ;------------------------------------------------------------
                                    550 ;b             Allocated with name '_mixed_signed_unsigned_PARM_2'
                                    551 ;a             Allocated to registers r6 r7 
                                    552 ;------------------------------------------------------------
                                    553 ;	arith_ext_int.c:22: int mixed_signed_unsigned(int a,unsigned int b){ return a + b; }
                                    554 ;	-----------------------------------------
                                    555 ;	 function mixed_signed_unsigned
                                    556 ;	-----------------------------------------
      00019F                        557 _mixed_signed_unsigned:
      00019F AE 82            [24]  558 	mov	r6, dpl
      0001A1 AF 83            [24]  559 	mov	r7, dph
      0001A3 E5 14            [12]  560 	mov	a,_mixed_signed_unsigned_PARM_2
      0001A5 2E               [12]  561 	add	a, r6
      0001A6 F5 82            [12]  562 	mov	dpl,a
      0001A8 E5 15            [12]  563 	mov	a,(_mixed_signed_unsigned_PARM_2 + 1)
      0001AA 3F               [12]  564 	addc	a, r7
      0001AB F5 83            [12]  565 	mov	dph,a
      0001AD 22               [24]  566 	ret
                                    567 ;------------------------------------------------------------
                                    568 ;Allocation info for local variables in function 'mixed_unsigned_signed'
                                    569 ;------------------------------------------------------------
                                    570 ;b             Allocated with name '_mixed_unsigned_signed_PARM_2'
                                    571 ;a             Allocated to registers r6 r7 
                                    572 ;------------------------------------------------------------
                                    573 ;	arith_ext_int.c:23: unsigned int mixed_unsigned_signed(unsigned int a,int b){ return a + b; }
                                    574 ;	-----------------------------------------
                                    575 ;	 function mixed_unsigned_signed
                                    576 ;	-----------------------------------------
      0001AE                        577 _mixed_unsigned_signed:
      0001AE AE 82            [24]  578 	mov	r6, dpl
      0001B0 AF 83            [24]  579 	mov	r7, dph
      0001B2 AC 14            [24]  580 	mov	r4,_mixed_unsigned_signed_PARM_2
      0001B4 AD 15            [24]  581 	mov	r5,(_mixed_unsigned_signed_PARM_2 + 1)
      0001B6 EC               [12]  582 	mov	a,r4
      0001B7 2E               [12]  583 	add	a, r6
      0001B8 F5 82            [12]  584 	mov	dpl,a
      0001BA ED               [12]  585 	mov	a,r5
      0001BB 3F               [12]  586 	addc	a, r7
      0001BC F5 83            [12]  587 	mov	dph,a
      0001BE 22               [24]  588 	ret
                                    589 ;------------------------------------------------------------
                                    590 ;Allocation info for local variables in function 'add_min_max'
                                    591 ;------------------------------------------------------------
                                    592 ;	arith_ext_int.c:25: int add_min_max(){ return 32767 + 1; }
                                    593 ;	-----------------------------------------
                                    594 ;	 function add_min_max
                                    595 ;	-----------------------------------------
      0001BF                        596 _add_min_max:
      0001BF 90 80 00         [24]  597 	mov	dptr,#0x8000
      0001C2 22               [24]  598 	ret
                                    599 ;------------------------------------------------------------
                                    600 ;Allocation info for local variables in function 'sub_min_max'
                                    601 ;------------------------------------------------------------
                                    602 ;	arith_ext_int.c:26: int sub_min_max(){ return (-32768) - 1; }
                                    603 ;	-----------------------------------------
                                    604 ;	 function sub_min_max
                                    605 ;	-----------------------------------------
      0001C3                        606 _sub_min_max:
      0001C3 90 7F FF         [24]  607 	mov	dptr,#0x7fff
      0001C6 22               [24]  608 	ret
                                    609 ;------------------------------------------------------------
                                    610 ;Allocation info for local variables in function 'main'
                                    611 ;------------------------------------------------------------
                                    612 ;	arith_ext_int.c:29: int main()
                                    613 ;	-----------------------------------------
                                    614 ;	 function main
                                    615 ;	-----------------------------------------
      0001C7                        616 _main:
                                    617 ;	arith_ext_int.c:31: return 0;
      0001C7 90 00 00         [24]  618 	mov	dptr,#0x0000
                                    619 ;	arith_ext_int.c:32: }
      0001CA 22               [24]  620 	ret
                                    621 	.area CSEG    (CODE)
                                    622 	.area CONST   (CODE)
                                    623 	.area XINIT   (CODE)
                                    624 	.area CABS    (ABS,CODE)
