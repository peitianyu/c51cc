                                      1 ;--------------------------------------------------------
                                      2 ; File Created by SDCC : free open source ISO C Compiler
                                      3 ; Version 4.5.0 #15242 (MINGW64)
                                      4 ;--------------------------------------------------------
                                      5 	.module cmp_signed_int
                                      6 	
                                      7 	.optsdcc -mmcs51 --model-small
                                      8 ;--------------------------------------------------------
                                      9 ; Public variables in this module
                                     10 ;--------------------------------------------------------
                                     11 	.globl _cmp_signed_ne_PARM_2
                                     12 	.globl _cmp_signed_eq_PARM_2
                                     13 	.globl _cmp_signed_ge_PARM_2
                                     14 	.globl _cmp_signed_gt_PARM_2
                                     15 	.globl _cmp_signed_le_PARM_2
                                     16 	.globl _cmp_signed_lt_PARM_2
                                     17 	.globl _main
                                     18 	.globl _cmp_signed_ne
                                     19 	.globl _cmp_signed_eq
                                     20 	.globl _cmp_signed_ge
                                     21 	.globl _cmp_signed_gt
                                     22 	.globl _cmp_signed_le
                                     23 	.globl _cmp_signed_lt
                                     24 ;--------------------------------------------------------
                                     25 ; special function registers
                                     26 ;--------------------------------------------------------
                                     27 	.area RSEG    (ABS,DATA)
      000000                         28 	.org 0x0000
                                     29 ;--------------------------------------------------------
                                     30 ; special function bits
                                     31 ;--------------------------------------------------------
                                     32 	.area RSEG    (ABS,DATA)
      000000                         33 	.org 0x0000
                                     34 ;--------------------------------------------------------
                                     35 ; overlayable register banks
                                     36 ;--------------------------------------------------------
                                     37 	.area REG_BANK_0	(REL,OVR,DATA)
      000000                         38 	.ds 8
                                     39 ;--------------------------------------------------------
                                     40 ; internal ram data
                                     41 ;--------------------------------------------------------
                                     42 	.area DSEG    (DATA)
                                     43 ;--------------------------------------------------------
                                     44 ; overlayable items in internal ram
                                     45 ;--------------------------------------------------------
                                     46 	.area	OSEG    (OVR,DATA)
      000008                         47 _cmp_signed_lt_PARM_2:
      000008                         48 	.ds 2
                                     49 	.area	OSEG    (OVR,DATA)
      000008                         50 _cmp_signed_le_PARM_2:
      000008                         51 	.ds 2
                                     52 	.area	OSEG    (OVR,DATA)
      000008                         53 _cmp_signed_gt_PARM_2:
      000008                         54 	.ds 2
                                     55 	.area	OSEG    (OVR,DATA)
      000008                         56 _cmp_signed_ge_PARM_2:
      000008                         57 	.ds 2
                                     58 	.area	OSEG    (OVR,DATA)
      000008                         59 _cmp_signed_eq_PARM_2:
      000008                         60 	.ds 2
                                     61 	.area	OSEG    (OVR,DATA)
      000008                         62 _cmp_signed_ne_PARM_2:
      000008                         63 	.ds 2
                                     64 ;--------------------------------------------------------
                                     65 ; Stack segment in internal ram
                                     66 ;--------------------------------------------------------
                                     67 	.area SSEG
      000021                         68 __start__stack:
      000021                         69 	.ds	1
                                     70 
                                     71 ;--------------------------------------------------------
                                     72 ; indirectly addressable internal ram data
                                     73 ;--------------------------------------------------------
                                     74 	.area ISEG    (DATA)
                                     75 ;--------------------------------------------------------
                                     76 ; absolute internal ram data
                                     77 ;--------------------------------------------------------
                                     78 	.area IABS    (ABS,DATA)
                                     79 	.area IABS    (ABS,DATA)
                                     80 ;--------------------------------------------------------
                                     81 ; bit data
                                     82 ;--------------------------------------------------------
                                     83 	.area BSEG    (BIT)
      000000                         84 _cmp_signed_le_sloc0_1_0:
      000000                         85 	.ds 1
      000001                         86 _cmp_signed_ge_sloc0_1_0:
      000001                         87 	.ds 1
      000002                         88 _cmp_signed_ne_sloc0_1_0:
      000002                         89 	.ds 1
                                     90 ;--------------------------------------------------------
                                     91 ; paged external ram data
                                     92 ;--------------------------------------------------------
                                     93 	.area PSEG    (PAG,XDATA)
                                     94 ;--------------------------------------------------------
                                     95 ; uninitialized external ram data
                                     96 ;--------------------------------------------------------
                                     97 	.area XSEG    (XDATA)
                                     98 ;--------------------------------------------------------
                                     99 ; absolute external ram data
                                    100 ;--------------------------------------------------------
                                    101 	.area XABS    (ABS,XDATA)
                                    102 ;--------------------------------------------------------
                                    103 ; initialized external ram data
                                    104 ;--------------------------------------------------------
                                    105 	.area XISEG   (XDATA)
                                    106 	.area HOME    (CODE)
                                    107 	.area GSINIT0 (CODE)
                                    108 	.area GSINIT1 (CODE)
                                    109 	.area GSINIT2 (CODE)
                                    110 	.area GSINIT3 (CODE)
                                    111 	.area GSINIT4 (CODE)
                                    112 	.area GSINIT5 (CODE)
                                    113 	.area GSINIT  (CODE)
                                    114 	.area GSFINAL (CODE)
                                    115 	.area CSEG    (CODE)
                                    116 ;--------------------------------------------------------
                                    117 ; interrupt vector
                                    118 ;--------------------------------------------------------
                                    119 	.area HOME    (CODE)
      000000                        120 __interrupt_vect:
      000000 02 00 4C         [24]  121 	ljmp	__sdcc_gsinit_startup
                                    122 ; restartable atomic support routines
      000003                        123 	.ds	5
      000008                        124 sdcc_atomic_exchange_rollback_start::
      000008 00               [12]  125 	nop
      000009 00               [12]  126 	nop
      00000A                        127 sdcc_atomic_exchange_pdata_impl:
      00000A E2               [24]  128 	movx	a, @r0
      00000B FB               [12]  129 	mov	r3, a
      00000C EA               [12]  130 	mov	a, r2
      00000D F2               [24]  131 	movx	@r0, a
      00000E 80 2C            [24]  132 	sjmp	sdcc_atomic_exchange_exit
      000010 00               [12]  133 	nop
      000011 00               [12]  134 	nop
      000012                        135 sdcc_atomic_exchange_xdata_impl:
      000012 E0               [24]  136 	movx	a, @dptr
      000013 FB               [12]  137 	mov	r3, a
      000014 EA               [12]  138 	mov	a, r2
      000015 F0               [24]  139 	movx	@dptr, a
      000016 80 24            [24]  140 	sjmp	sdcc_atomic_exchange_exit
      000018                        141 sdcc_atomic_compare_exchange_idata_impl:
      000018 E6               [12]  142 	mov	a, @r0
      000019 B5 02 02         [24]  143 	cjne	a, ar2, .+#5
      00001C EB               [12]  144 	mov	a, r3
      00001D F6               [12]  145 	mov	@r0, a
      00001E 22               [24]  146 	ret
      00001F 00               [12]  147 	nop
      000020                        148 sdcc_atomic_compare_exchange_pdata_impl:
      000020 E2               [24]  149 	movx	a, @r0
      000021 B5 02 02         [24]  150 	cjne	a, ar2, .+#5
      000024 EB               [12]  151 	mov	a, r3
      000025 F2               [24]  152 	movx	@r0, a
      000026 22               [24]  153 	ret
      000027 00               [12]  154 	nop
      000028                        155 sdcc_atomic_compare_exchange_xdata_impl:
      000028 E0               [24]  156 	movx	a, @dptr
      000029 B5 02 02         [24]  157 	cjne	a, ar2, .+#5
      00002C EB               [12]  158 	mov	a, r3
      00002D F0               [24]  159 	movx	@dptr, a
      00002E 22               [24]  160 	ret
      00002F                        161 sdcc_atomic_exchange_rollback_end::
                                    162 
      00002F                        163 sdcc_atomic_exchange_gptr_impl::
      00002F 30 F6 E0         [24]  164 	jnb	b.6, sdcc_atomic_exchange_xdata_impl
      000032 A8 82            [24]  165 	mov	r0, dpl
      000034 20 F5 D3         [24]  166 	jb	b.5, sdcc_atomic_exchange_pdata_impl
      000037                        167 sdcc_atomic_exchange_idata_impl:
      000037 EA               [12]  168 	mov	a, r2
      000038 C6               [12]  169 	xch	a, @r0
      000039 F5 82            [12]  170 	mov	dpl, a
      00003B 22               [24]  171 	ret
      00003C                        172 sdcc_atomic_exchange_exit:
      00003C 8B 82            [24]  173 	mov	dpl, r3
      00003E 22               [24]  174 	ret
      00003F                        175 sdcc_atomic_compare_exchange_gptr_impl::
      00003F 30 F6 E6         [24]  176 	jnb	b.6, sdcc_atomic_compare_exchange_xdata_impl
      000042 A8 82            [24]  177 	mov	r0, dpl
      000044 20 F5 D9         [24]  178 	jb	b.5, sdcc_atomic_compare_exchange_pdata_impl
      000047 80 CF            [24]  179 	sjmp	sdcc_atomic_compare_exchange_idata_impl
                                    180 ;--------------------------------------------------------
                                    181 ; global & static initialisations
                                    182 ;--------------------------------------------------------
                                    183 	.area HOME    (CODE)
                                    184 	.area GSINIT  (CODE)
                                    185 	.area GSFINAL (CODE)
                                    186 	.area GSINIT  (CODE)
                                    187 	.globl __sdcc_gsinit_startup
                                    188 	.globl __sdcc_program_startup
                                    189 	.globl __start__stack
                                    190 	.globl __mcs51_genXINIT
                                    191 	.globl __mcs51_genXRAMCLEAR
                                    192 	.globl __mcs51_genRAMCLEAR
                                    193 	.area GSFINAL (CODE)
      0000A5 02 00 49         [24]  194 	ljmp	__sdcc_program_startup
                                    195 ;--------------------------------------------------------
                                    196 ; Home
                                    197 ;--------------------------------------------------------
                                    198 	.area HOME    (CODE)
                                    199 	.area HOME    (CODE)
      000049                        200 __sdcc_program_startup:
      000049 02 01 58         [24]  201 	ljmp	_main
                                    202 ;	return from main will return to caller
                                    203 ;--------------------------------------------------------
                                    204 ; code
                                    205 ;--------------------------------------------------------
                                    206 	.area CSEG    (CODE)
                                    207 ;------------------------------------------------------------
                                    208 ;Allocation info for local variables in function 'cmp_signed_lt'
                                    209 ;------------------------------------------------------------
                                    210 ;b             Allocated with name '_cmp_signed_lt_PARM_2'
                                    211 ;a             Allocated to registers r6 r7 
                                    212 ;------------------------------------------------------------
                                    213 ;	cmp_signed_int.c:1: int cmp_signed_lt(int a,int b){ return a < b; }
                                    214 ;	-----------------------------------------
                                    215 ;	 function cmp_signed_lt
                                    216 ;	-----------------------------------------
      0000A8                        217 _cmp_signed_lt:
                           000007   218 	ar7 = 0x07
                           000006   219 	ar6 = 0x06
                           000005   220 	ar5 = 0x05
                           000004   221 	ar4 = 0x04
                           000003   222 	ar3 = 0x03
                           000002   223 	ar2 = 0x02
                           000001   224 	ar1 = 0x01
                           000000   225 	ar0 = 0x00
      0000A8 AE 82            [24]  226 	mov	r6, dpl
      0000AA AF 83            [24]  227 	mov	r7, dph
      0000AC C3               [12]  228 	clr	c
      0000AD EE               [12]  229 	mov	a,r6
      0000AE 95 08            [12]  230 	subb	a,_cmp_signed_lt_PARM_2
      0000B0 EF               [12]  231 	mov	a,r7
      0000B1 64 80            [12]  232 	xrl	a,#0x80
      0000B3 85 09 F0         [24]  233 	mov	b,(_cmp_signed_lt_PARM_2 + 1)
      0000B6 63 F0 80         [24]  234 	xrl	b,#0x80
      0000B9 95 F0            [12]  235 	subb	a,b
      0000BB E4               [12]  236 	clr	a
      0000BC 33               [12]  237 	rlc	a
      0000BD FE               [12]  238 	mov	r6,a
      0000BE 7F 00            [12]  239 	mov	r7,#0x00
      0000C0 8E 82            [24]  240 	mov	dpl, r6
      0000C2 8F 83            [24]  241 	mov	dph, r7
      0000C4 22               [24]  242 	ret
                                    243 ;------------------------------------------------------------
                                    244 ;Allocation info for local variables in function 'cmp_signed_le'
                                    245 ;------------------------------------------------------------
                                    246 ;b             Allocated with name '_cmp_signed_le_PARM_2'
                                    247 ;a             Allocated to registers r6 r7 
                                    248 ;------------------------------------------------------------
                                    249 ;	cmp_signed_int.c:2: int cmp_signed_le(int a,int b){ return a <= b; }
                                    250 ;	-----------------------------------------
                                    251 ;	 function cmp_signed_le
                                    252 ;	-----------------------------------------
      0000C5                        253 _cmp_signed_le:
      0000C5 AE 82            [24]  254 	mov	r6, dpl
      0000C7 AF 83            [24]  255 	mov	r7, dph
      0000C9 C3               [12]  256 	clr	c
      0000CA E5 08            [12]  257 	mov	a,_cmp_signed_le_PARM_2
      0000CC 9E               [12]  258 	subb	a,r6
      0000CD E5 09            [12]  259 	mov	a,(_cmp_signed_le_PARM_2 + 1)
      0000CF 64 80            [12]  260 	xrl	a,#0x80
      0000D1 8F F0            [24]  261 	mov	b,r7
      0000D3 63 F0 80         [24]  262 	xrl	b,#0x80
      0000D6 95 F0            [12]  263 	subb	a,b
      0000D8 B3               [12]  264 	cpl	c
      0000D9 92 00            [24]  265 	mov	_cmp_signed_le_sloc0_1_0,c
      0000DB E4               [12]  266 	clr	a
      0000DC 33               [12]  267 	rlc	a
      0000DD FE               [12]  268 	mov	r6,a
      0000DE 7F 00            [12]  269 	mov	r7,#0x00
      0000E0 8E 82            [24]  270 	mov	dpl, r6
      0000E2 8F 83            [24]  271 	mov	dph, r7
      0000E4 22               [24]  272 	ret
                                    273 ;------------------------------------------------------------
                                    274 ;Allocation info for local variables in function 'cmp_signed_gt'
                                    275 ;------------------------------------------------------------
                                    276 ;b             Allocated with name '_cmp_signed_gt_PARM_2'
                                    277 ;a             Allocated to registers r6 r7 
                                    278 ;------------------------------------------------------------
                                    279 ;	cmp_signed_int.c:3: int cmp_signed_gt(int a,int b){ return a > b; }
                                    280 ;	-----------------------------------------
                                    281 ;	 function cmp_signed_gt
                                    282 ;	-----------------------------------------
      0000E5                        283 _cmp_signed_gt:
      0000E5 AE 82            [24]  284 	mov	r6, dpl
      0000E7 AF 83            [24]  285 	mov	r7, dph
      0000E9 C3               [12]  286 	clr	c
      0000EA E5 08            [12]  287 	mov	a,_cmp_signed_gt_PARM_2
      0000EC 9E               [12]  288 	subb	a,r6
      0000ED E5 09            [12]  289 	mov	a,(_cmp_signed_gt_PARM_2 + 1)
      0000EF 64 80            [12]  290 	xrl	a,#0x80
      0000F1 8F F0            [24]  291 	mov	b,r7
      0000F3 63 F0 80         [24]  292 	xrl	b,#0x80
      0000F6 95 F0            [12]  293 	subb	a,b
      0000F8 E4               [12]  294 	clr	a
      0000F9 33               [12]  295 	rlc	a
      0000FA FE               [12]  296 	mov	r6,a
      0000FB 7F 00            [12]  297 	mov	r7,#0x00
      0000FD 8E 82            [24]  298 	mov	dpl, r6
      0000FF 8F 83            [24]  299 	mov	dph, r7
      000101 22               [24]  300 	ret
                                    301 ;------------------------------------------------------------
                                    302 ;Allocation info for local variables in function 'cmp_signed_ge'
                                    303 ;------------------------------------------------------------
                                    304 ;b             Allocated with name '_cmp_signed_ge_PARM_2'
                                    305 ;a             Allocated to registers r6 r7 
                                    306 ;------------------------------------------------------------
                                    307 ;	cmp_signed_int.c:4: int cmp_signed_ge(int a,int b){ return a >= b; }
                                    308 ;	-----------------------------------------
                                    309 ;	 function cmp_signed_ge
                                    310 ;	-----------------------------------------
      000102                        311 _cmp_signed_ge:
      000102 AE 82            [24]  312 	mov	r6, dpl
      000104 AF 83            [24]  313 	mov	r7, dph
      000106 C3               [12]  314 	clr	c
      000107 EE               [12]  315 	mov	a,r6
      000108 95 08            [12]  316 	subb	a,_cmp_signed_ge_PARM_2
      00010A EF               [12]  317 	mov	a,r7
      00010B 64 80            [12]  318 	xrl	a,#0x80
      00010D 85 09 F0         [24]  319 	mov	b,(_cmp_signed_ge_PARM_2 + 1)
      000110 63 F0 80         [24]  320 	xrl	b,#0x80
      000113 95 F0            [12]  321 	subb	a,b
      000115 B3               [12]  322 	cpl	c
      000116 92 01            [24]  323 	mov	_cmp_signed_ge_sloc0_1_0,c
      000118 E4               [12]  324 	clr	a
      000119 33               [12]  325 	rlc	a
      00011A FE               [12]  326 	mov	r6,a
      00011B 7F 00            [12]  327 	mov	r7,#0x00
      00011D 8E 82            [24]  328 	mov	dpl, r6
      00011F 8F 83            [24]  329 	mov	dph, r7
      000121 22               [24]  330 	ret
                                    331 ;------------------------------------------------------------
                                    332 ;Allocation info for local variables in function 'cmp_signed_eq'
                                    333 ;------------------------------------------------------------
                                    334 ;b             Allocated with name '_cmp_signed_eq_PARM_2'
                                    335 ;a             Allocated to registers r6 r7 
                                    336 ;------------------------------------------------------------
                                    337 ;	cmp_signed_int.c:5: int cmp_signed_eq(int a,int b){ return a == b; }
                                    338 ;	-----------------------------------------
                                    339 ;	 function cmp_signed_eq
                                    340 ;	-----------------------------------------
      000122                        341 _cmp_signed_eq:
      000122 AE 82            [24]  342 	mov	r6, dpl
      000124 AF 83            [24]  343 	mov	r7, dph
      000126 EE               [12]  344 	mov	a,r6
      000127 B5 08 08         [24]  345 	cjne	a,_cmp_signed_eq_PARM_2,00103$
      00012A EF               [12]  346 	mov	a,r7
      00012B B5 09 04         [24]  347 	cjne	a,(_cmp_signed_eq_PARM_2 + 1),00103$
      00012E 74 01            [12]  348 	mov	a,#0x01
      000130 80 01            [24]  349 	sjmp	00104$
      000132                        350 00103$:
      000132 E4               [12]  351 	clr	a
      000133                        352 00104$:
      000133 FE               [12]  353 	mov	r6,a
      000134 7F 00            [12]  354 	mov	r7,#0x00
      000136 8E 82            [24]  355 	mov	dpl, r6
      000138 8F 83            [24]  356 	mov	dph, r7
      00013A 22               [24]  357 	ret
                                    358 ;------------------------------------------------------------
                                    359 ;Allocation info for local variables in function 'cmp_signed_ne'
                                    360 ;------------------------------------------------------------
                                    361 ;b             Allocated with name '_cmp_signed_ne_PARM_2'
                                    362 ;a             Allocated to registers r6 r7 
                                    363 ;------------------------------------------------------------
                                    364 ;	cmp_signed_int.c:6: int cmp_signed_ne(int a,int b){ return a != b; }
                                    365 ;	-----------------------------------------
                                    366 ;	 function cmp_signed_ne
                                    367 ;	-----------------------------------------
      00013B                        368 _cmp_signed_ne:
      00013B AE 82            [24]  369 	mov	r6, dpl
      00013D AF 83            [24]  370 	mov	r7, dph
      00013F EE               [12]  371 	mov	a,r6
      000140 B5 08 07         [24]  372 	cjne	a,_cmp_signed_ne_PARM_2,00103$
      000143 EF               [12]  373 	mov	a,r7
      000144 B5 09 03         [24]  374 	cjne	a,(_cmp_signed_ne_PARM_2 + 1),00103$
      000147 D3               [12]  375 	setb	c
      000148 80 01            [24]  376 	sjmp	00104$
      00014A                        377 00103$:
      00014A C3               [12]  378 	clr	c
      00014B                        379 00104$:
      00014B B3               [12]  380 	cpl	c
      00014C 92 02            [24]  381 	mov	_cmp_signed_ne_sloc0_1_0,c
      00014E E4               [12]  382 	clr	a
      00014F 33               [12]  383 	rlc	a
      000150 FE               [12]  384 	mov	r6,a
      000151 7F 00            [12]  385 	mov	r7,#0x00
      000153 8E 82            [24]  386 	mov	dpl, r6
      000155 8F 83            [24]  387 	mov	dph, r7
      000157 22               [24]  388 	ret
                                    389 ;------------------------------------------------------------
                                    390 ;Allocation info for local variables in function 'main'
                                    391 ;------------------------------------------------------------
                                    392 ;	cmp_signed_int.c:8: int main()
                                    393 ;	-----------------------------------------
                                    394 ;	 function main
                                    395 ;	-----------------------------------------
      000158                        396 _main:
                                    397 ;	cmp_signed_int.c:10: return 0;
      000158 90 00 00         [24]  398 	mov	dptr,#0x0000
                                    399 ;	cmp_signed_int.c:11: }
      00015B 22               [24]  400 	ret
                                    401 	.area CSEG    (CODE)
                                    402 	.area CONST   (CODE)
                                    403 	.area XINIT   (CODE)
                                    404 	.area CABS    (ABS,CODE)
