                                      1 ;--------------------------------------------------------
                                      2 ; File Created by SDCC : free open source ISO C Compiler
                                      3 ; Version 4.5.0 #15242 (MINGW64)
                                      4 ;--------------------------------------------------------
                                      5 	.module cmp_unsigned_int
                                      6 	
                                      7 	.optsdcc -mmcs51 --model-small
                                      8 ;--------------------------------------------------------
                                      9 ; Public variables in this module
                                     10 ;--------------------------------------------------------
                                     11 	.globl _cmp_unsigned_ne_PARM_2
                                     12 	.globl _cmp_unsigned_eq_PARM_2
                                     13 	.globl _cmp_unsigned_ge_PARM_2
                                     14 	.globl _cmp_unsigned_gt_PARM_2
                                     15 	.globl _cmp_unsigned_le_PARM_2
                                     16 	.globl _cmp_unsigned_lt_PARM_2
                                     17 	.globl _main
                                     18 	.globl _cmp_unsigned_ne
                                     19 	.globl _cmp_unsigned_eq
                                     20 	.globl _cmp_unsigned_ge
                                     21 	.globl _cmp_unsigned_gt
                                     22 	.globl _cmp_unsigned_le
                                     23 	.globl _cmp_unsigned_lt
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
      000008                         47 _cmp_unsigned_lt_PARM_2:
      000008                         48 	.ds 2
                                     49 	.area	OSEG    (OVR,DATA)
      000008                         50 _cmp_unsigned_le_PARM_2:
      000008                         51 	.ds 2
                                     52 	.area	OSEG    (OVR,DATA)
      000008                         53 _cmp_unsigned_gt_PARM_2:
      000008                         54 	.ds 2
                                     55 	.area	OSEG    (OVR,DATA)
      000008                         56 _cmp_unsigned_ge_PARM_2:
      000008                         57 	.ds 2
                                     58 	.area	OSEG    (OVR,DATA)
      000008                         59 _cmp_unsigned_eq_PARM_2:
      000008                         60 	.ds 2
                                     61 	.area	OSEG    (OVR,DATA)
      000008                         62 _cmp_unsigned_ne_PARM_2:
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
      000000                         84 _cmp_unsigned_le_sloc0_1_0:
      000000                         85 	.ds 1
      000001                         86 _cmp_unsigned_ge_sloc0_1_0:
      000001                         87 	.ds 1
      000002                         88 _cmp_unsigned_ne_sloc0_1_0:
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
      000049 02 01 38         [24]  201 	ljmp	_main
                                    202 ;	return from main will return to caller
                                    203 ;--------------------------------------------------------
                                    204 ; code
                                    205 ;--------------------------------------------------------
                                    206 	.area CSEG    (CODE)
                                    207 ;------------------------------------------------------------
                                    208 ;Allocation info for local variables in function 'cmp_unsigned_lt'
                                    209 ;------------------------------------------------------------
                                    210 ;b             Allocated with name '_cmp_unsigned_lt_PARM_2'
                                    211 ;a             Allocated to registers r6 r7 
                                    212 ;------------------------------------------------------------
                                    213 ;	cmp_unsigned_int.c:1: unsigned int cmp_unsigned_lt(unsigned int a,unsigned int b){ return a < b; }
                                    214 ;	-----------------------------------------
                                    215 ;	 function cmp_unsigned_lt
                                    216 ;	-----------------------------------------
      0000A8                        217 _cmp_unsigned_lt:
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
      0000AE 95 08            [12]  230 	subb	a,_cmp_unsigned_lt_PARM_2
      0000B0 EF               [12]  231 	mov	a,r7
      0000B1 95 09            [12]  232 	subb	a,(_cmp_unsigned_lt_PARM_2 + 1)
      0000B3 E4               [12]  233 	clr	a
      0000B4 33               [12]  234 	rlc	a
      0000B5 FE               [12]  235 	mov	r6,a
      0000B6 7F 00            [12]  236 	mov	r7,#0x00
      0000B8 8E 82            [24]  237 	mov	dpl, r6
      0000BA 8F 83            [24]  238 	mov	dph, r7
      0000BC 22               [24]  239 	ret
                                    240 ;------------------------------------------------------------
                                    241 ;Allocation info for local variables in function 'cmp_unsigned_le'
                                    242 ;------------------------------------------------------------
                                    243 ;b             Allocated with name '_cmp_unsigned_le_PARM_2'
                                    244 ;a             Allocated to registers r6 r7 
                                    245 ;------------------------------------------------------------
                                    246 ;	cmp_unsigned_int.c:2: unsigned int cmp_unsigned_le(unsigned int a,unsigned int b){ return a <= b; }
                                    247 ;	-----------------------------------------
                                    248 ;	 function cmp_unsigned_le
                                    249 ;	-----------------------------------------
      0000BD                        250 _cmp_unsigned_le:
      0000BD AE 82            [24]  251 	mov	r6, dpl
      0000BF AF 83            [24]  252 	mov	r7, dph
      0000C1 C3               [12]  253 	clr	c
      0000C2 E5 08            [12]  254 	mov	a,_cmp_unsigned_le_PARM_2
      0000C4 9E               [12]  255 	subb	a,r6
      0000C5 E5 09            [12]  256 	mov	a,(_cmp_unsigned_le_PARM_2 + 1)
      0000C7 9F               [12]  257 	subb	a,r7
      0000C8 B3               [12]  258 	cpl	c
      0000C9 92 00            [24]  259 	mov	_cmp_unsigned_le_sloc0_1_0,c
      0000CB E4               [12]  260 	clr	a
      0000CC 33               [12]  261 	rlc	a
      0000CD FE               [12]  262 	mov	r6,a
      0000CE 7F 00            [12]  263 	mov	r7,#0x00
      0000D0 8E 82            [24]  264 	mov	dpl, r6
      0000D2 8F 83            [24]  265 	mov	dph, r7
      0000D4 22               [24]  266 	ret
                                    267 ;------------------------------------------------------------
                                    268 ;Allocation info for local variables in function 'cmp_unsigned_gt'
                                    269 ;------------------------------------------------------------
                                    270 ;b             Allocated with name '_cmp_unsigned_gt_PARM_2'
                                    271 ;a             Allocated to registers r6 r7 
                                    272 ;------------------------------------------------------------
                                    273 ;	cmp_unsigned_int.c:3: unsigned int cmp_unsigned_gt(unsigned int a,unsigned int b){ return a > b; }
                                    274 ;	-----------------------------------------
                                    275 ;	 function cmp_unsigned_gt
                                    276 ;	-----------------------------------------
      0000D5                        277 _cmp_unsigned_gt:
      0000D5 AE 82            [24]  278 	mov	r6, dpl
      0000D7 AF 83            [24]  279 	mov	r7, dph
      0000D9 C3               [12]  280 	clr	c
      0000DA E5 08            [12]  281 	mov	a,_cmp_unsigned_gt_PARM_2
      0000DC 9E               [12]  282 	subb	a,r6
      0000DD E5 09            [12]  283 	mov	a,(_cmp_unsigned_gt_PARM_2 + 1)
      0000DF 9F               [12]  284 	subb	a,r7
      0000E0 E4               [12]  285 	clr	a
      0000E1 33               [12]  286 	rlc	a
      0000E2 FE               [12]  287 	mov	r6,a
      0000E3 7F 00            [12]  288 	mov	r7,#0x00
      0000E5 8E 82            [24]  289 	mov	dpl, r6
      0000E7 8F 83            [24]  290 	mov	dph, r7
      0000E9 22               [24]  291 	ret
                                    292 ;------------------------------------------------------------
                                    293 ;Allocation info for local variables in function 'cmp_unsigned_ge'
                                    294 ;------------------------------------------------------------
                                    295 ;b             Allocated with name '_cmp_unsigned_ge_PARM_2'
                                    296 ;a             Allocated to registers r6 r7 
                                    297 ;------------------------------------------------------------
                                    298 ;	cmp_unsigned_int.c:4: unsigned int cmp_unsigned_ge(unsigned int a,unsigned int b){ return a >= b; }
                                    299 ;	-----------------------------------------
                                    300 ;	 function cmp_unsigned_ge
                                    301 ;	-----------------------------------------
      0000EA                        302 _cmp_unsigned_ge:
      0000EA AE 82            [24]  303 	mov	r6, dpl
      0000EC AF 83            [24]  304 	mov	r7, dph
      0000EE C3               [12]  305 	clr	c
      0000EF EE               [12]  306 	mov	a,r6
      0000F0 95 08            [12]  307 	subb	a,_cmp_unsigned_ge_PARM_2
      0000F2 EF               [12]  308 	mov	a,r7
      0000F3 95 09            [12]  309 	subb	a,(_cmp_unsigned_ge_PARM_2 + 1)
      0000F5 B3               [12]  310 	cpl	c
      0000F6 92 01            [24]  311 	mov	_cmp_unsigned_ge_sloc0_1_0,c
      0000F8 E4               [12]  312 	clr	a
      0000F9 33               [12]  313 	rlc	a
      0000FA FE               [12]  314 	mov	r6,a
      0000FB 7F 00            [12]  315 	mov	r7,#0x00
      0000FD 8E 82            [24]  316 	mov	dpl, r6
      0000FF 8F 83            [24]  317 	mov	dph, r7
      000101 22               [24]  318 	ret
                                    319 ;------------------------------------------------------------
                                    320 ;Allocation info for local variables in function 'cmp_unsigned_eq'
                                    321 ;------------------------------------------------------------
                                    322 ;b             Allocated with name '_cmp_unsigned_eq_PARM_2'
                                    323 ;a             Allocated to registers r6 r7 
                                    324 ;------------------------------------------------------------
                                    325 ;	cmp_unsigned_int.c:5: unsigned int cmp_unsigned_eq(unsigned int a,unsigned int b){ return a == b; }
                                    326 ;	-----------------------------------------
                                    327 ;	 function cmp_unsigned_eq
                                    328 ;	-----------------------------------------
      000102                        329 _cmp_unsigned_eq:
      000102 AE 82            [24]  330 	mov	r6, dpl
      000104 AF 83            [24]  331 	mov	r7, dph
      000106 EE               [12]  332 	mov	a,r6
      000107 B5 08 08         [24]  333 	cjne	a,_cmp_unsigned_eq_PARM_2,00103$
      00010A EF               [12]  334 	mov	a,r7
      00010B B5 09 04         [24]  335 	cjne	a,(_cmp_unsigned_eq_PARM_2 + 1),00103$
      00010E 74 01            [12]  336 	mov	a,#0x01
      000110 80 01            [24]  337 	sjmp	00104$
      000112                        338 00103$:
      000112 E4               [12]  339 	clr	a
      000113                        340 00104$:
      000113 FE               [12]  341 	mov	r6,a
      000114 7F 00            [12]  342 	mov	r7,#0x00
      000116 8E 82            [24]  343 	mov	dpl, r6
      000118 8F 83            [24]  344 	mov	dph, r7
      00011A 22               [24]  345 	ret
                                    346 ;------------------------------------------------------------
                                    347 ;Allocation info for local variables in function 'cmp_unsigned_ne'
                                    348 ;------------------------------------------------------------
                                    349 ;b             Allocated with name '_cmp_unsigned_ne_PARM_2'
                                    350 ;a             Allocated to registers r6 r7 
                                    351 ;------------------------------------------------------------
                                    352 ;	cmp_unsigned_int.c:6: unsigned int cmp_unsigned_ne(unsigned int a,unsigned int b){ return a != b; }
                                    353 ;	-----------------------------------------
                                    354 ;	 function cmp_unsigned_ne
                                    355 ;	-----------------------------------------
      00011B                        356 _cmp_unsigned_ne:
      00011B AE 82            [24]  357 	mov	r6, dpl
      00011D AF 83            [24]  358 	mov	r7, dph
      00011F EE               [12]  359 	mov	a,r6
      000120 B5 08 07         [24]  360 	cjne	a,_cmp_unsigned_ne_PARM_2,00103$
      000123 EF               [12]  361 	mov	a,r7
      000124 B5 09 03         [24]  362 	cjne	a,(_cmp_unsigned_ne_PARM_2 + 1),00103$
      000127 D3               [12]  363 	setb	c
      000128 80 01            [24]  364 	sjmp	00104$
      00012A                        365 00103$:
      00012A C3               [12]  366 	clr	c
      00012B                        367 00104$:
      00012B B3               [12]  368 	cpl	c
      00012C 92 02            [24]  369 	mov	_cmp_unsigned_ne_sloc0_1_0,c
      00012E E4               [12]  370 	clr	a
      00012F 33               [12]  371 	rlc	a
      000130 FE               [12]  372 	mov	r6,a
      000131 7F 00            [12]  373 	mov	r7,#0x00
      000133 8E 82            [24]  374 	mov	dpl, r6
      000135 8F 83            [24]  375 	mov	dph, r7
      000137 22               [24]  376 	ret
                                    377 ;------------------------------------------------------------
                                    378 ;Allocation info for local variables in function 'main'
                                    379 ;------------------------------------------------------------
                                    380 ;	cmp_unsigned_int.c:8: int main()
                                    381 ;	-----------------------------------------
                                    382 ;	 function main
                                    383 ;	-----------------------------------------
      000138                        384 _main:
                                    385 ;	cmp_unsigned_int.c:10: return 0;
      000138 90 00 00         [24]  386 	mov	dptr,#0x0000
                                    387 ;	cmp_unsigned_int.c:11: }
      00013B 22               [24]  388 	ret
                                    389 	.area CSEG    (CODE)
                                    390 	.area CONST   (CODE)
                                    391 	.area XINIT   (CODE)
                                    392 	.area CABS    (ABS,CODE)
