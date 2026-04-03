                                      1 ;--------------------------------------------------------
                                      2 ; File Created by SDCC : free open source ISO C Compiler
                                      3 ; Version 4.5.0 #15242 (MINGW64)
                                      4 ;--------------------------------------------------------
                                      5 	.module func_add_sub
                                      6 	
                                      7 	.optsdcc -mmcs51 --model-small
                                      8 ;--------------------------------------------------------
                                      9 ; Public variables in this module
                                     10 ;--------------------------------------------------------
                                     11 	.globl _add_sub_PARM_2
                                     12 	.globl _main
                                     13 	.globl _add_sub
                                     14 ;--------------------------------------------------------
                                     15 ; special function registers
                                     16 ;--------------------------------------------------------
                                     17 	.area RSEG    (ABS,DATA)
      000000                         18 	.org 0x0000
                                     19 ;--------------------------------------------------------
                                     20 ; special function bits
                                     21 ;--------------------------------------------------------
                                     22 	.area RSEG    (ABS,DATA)
      000000                         23 	.org 0x0000
                                     24 ;--------------------------------------------------------
                                     25 ; overlayable register banks
                                     26 ;--------------------------------------------------------
                                     27 	.area REG_BANK_0	(REL,OVR,DATA)
      000000                         28 	.ds 8
                                     29 ;--------------------------------------------------------
                                     30 ; internal ram data
                                     31 ;--------------------------------------------------------
                                     32 	.area DSEG    (DATA)
                                     33 ;--------------------------------------------------------
                                     34 ; overlayable items in internal ram
                                     35 ;--------------------------------------------------------
                                     36 	.area	OSEG    (OVR,DATA)
      000008                         37 _add_sub_PARM_2:
      000008                         38 	.ds 1
                                     39 ;--------------------------------------------------------
                                     40 ; Stack segment in internal ram
                                     41 ;--------------------------------------------------------
                                     42 	.area SSEG
      000009                         43 __start__stack:
      000009                         44 	.ds	1
                                     45 
                                     46 ;--------------------------------------------------------
                                     47 ; indirectly addressable internal ram data
                                     48 ;--------------------------------------------------------
                                     49 	.area ISEG    (DATA)
                                     50 ;--------------------------------------------------------
                                     51 ; absolute internal ram data
                                     52 ;--------------------------------------------------------
                                     53 	.area IABS    (ABS,DATA)
                                     54 	.area IABS    (ABS,DATA)
                                     55 ;--------------------------------------------------------
                                     56 ; bit data
                                     57 ;--------------------------------------------------------
                                     58 	.area BSEG    (BIT)
                                     59 ;--------------------------------------------------------
                                     60 ; paged external ram data
                                     61 ;--------------------------------------------------------
                                     62 	.area PSEG    (PAG,XDATA)
                                     63 ;--------------------------------------------------------
                                     64 ; uninitialized external ram data
                                     65 ;--------------------------------------------------------
                                     66 	.area XSEG    (XDATA)
                                     67 ;--------------------------------------------------------
                                     68 ; absolute external ram data
                                     69 ;--------------------------------------------------------
                                     70 	.area XABS    (ABS,XDATA)
                                     71 ;--------------------------------------------------------
                                     72 ; initialized external ram data
                                     73 ;--------------------------------------------------------
                                     74 	.area XISEG   (XDATA)
                                     75 	.area HOME    (CODE)
                                     76 	.area GSINIT0 (CODE)
                                     77 	.area GSINIT1 (CODE)
                                     78 	.area GSINIT2 (CODE)
                                     79 	.area GSINIT3 (CODE)
                                     80 	.area GSINIT4 (CODE)
                                     81 	.area GSINIT5 (CODE)
                                     82 	.area GSINIT  (CODE)
                                     83 	.area GSFINAL (CODE)
                                     84 	.area CSEG    (CODE)
                                     85 ;--------------------------------------------------------
                                     86 ; interrupt vector
                                     87 ;--------------------------------------------------------
                                     88 	.area HOME    (CODE)
      000000                         89 __interrupt_vect:
      000000 02 00 4C         [24]   90 	ljmp	__sdcc_gsinit_startup
                                     91 ; restartable atomic support routines
      000003                         92 	.ds	5
      000008                         93 sdcc_atomic_exchange_rollback_start::
      000008 00               [12]   94 	nop
      000009 00               [12]   95 	nop
      00000A                         96 sdcc_atomic_exchange_pdata_impl:
      00000A E2               [24]   97 	movx	a, @r0
      00000B FB               [12]   98 	mov	r3, a
      00000C EA               [12]   99 	mov	a, r2
      00000D F2               [24]  100 	movx	@r0, a
      00000E 80 2C            [24]  101 	sjmp	sdcc_atomic_exchange_exit
      000010 00               [12]  102 	nop
      000011 00               [12]  103 	nop
      000012                        104 sdcc_atomic_exchange_xdata_impl:
      000012 E0               [24]  105 	movx	a, @dptr
      000013 FB               [12]  106 	mov	r3, a
      000014 EA               [12]  107 	mov	a, r2
      000015 F0               [24]  108 	movx	@dptr, a
      000016 80 24            [24]  109 	sjmp	sdcc_atomic_exchange_exit
      000018                        110 sdcc_atomic_compare_exchange_idata_impl:
      000018 E6               [12]  111 	mov	a, @r0
      000019 B5 02 02         [24]  112 	cjne	a, ar2, .+#5
      00001C EB               [12]  113 	mov	a, r3
      00001D F6               [12]  114 	mov	@r0, a
      00001E 22               [24]  115 	ret
      00001F 00               [12]  116 	nop
      000020                        117 sdcc_atomic_compare_exchange_pdata_impl:
      000020 E2               [24]  118 	movx	a, @r0
      000021 B5 02 02         [24]  119 	cjne	a, ar2, .+#5
      000024 EB               [12]  120 	mov	a, r3
      000025 F2               [24]  121 	movx	@r0, a
      000026 22               [24]  122 	ret
      000027 00               [12]  123 	nop
      000028                        124 sdcc_atomic_compare_exchange_xdata_impl:
      000028 E0               [24]  125 	movx	a, @dptr
      000029 B5 02 02         [24]  126 	cjne	a, ar2, .+#5
      00002C EB               [12]  127 	mov	a, r3
      00002D F0               [24]  128 	movx	@dptr, a
      00002E 22               [24]  129 	ret
      00002F                        130 sdcc_atomic_exchange_rollback_end::
                                    131 
      00002F                        132 sdcc_atomic_exchange_gptr_impl::
      00002F 30 F6 E0         [24]  133 	jnb	b.6, sdcc_atomic_exchange_xdata_impl
      000032 A8 82            [24]  134 	mov	r0, dpl
      000034 20 F5 D3         [24]  135 	jb	b.5, sdcc_atomic_exchange_pdata_impl
      000037                        136 sdcc_atomic_exchange_idata_impl:
      000037 EA               [12]  137 	mov	a, r2
      000038 C6               [12]  138 	xch	a, @r0
      000039 F5 82            [12]  139 	mov	dpl, a
      00003B 22               [24]  140 	ret
      00003C                        141 sdcc_atomic_exchange_exit:
      00003C 8B 82            [24]  142 	mov	dpl, r3
      00003E 22               [24]  143 	ret
      00003F                        144 sdcc_atomic_compare_exchange_gptr_impl::
      00003F 30 F6 E6         [24]  145 	jnb	b.6, sdcc_atomic_compare_exchange_xdata_impl
      000042 A8 82            [24]  146 	mov	r0, dpl
      000044 20 F5 D9         [24]  147 	jb	b.5, sdcc_atomic_compare_exchange_pdata_impl
      000047 80 CF            [24]  148 	sjmp	sdcc_atomic_compare_exchange_idata_impl
                                    149 ;--------------------------------------------------------
                                    150 ; global & static initialisations
                                    151 ;--------------------------------------------------------
                                    152 	.area HOME    (CODE)
                                    153 	.area GSINIT  (CODE)
                                    154 	.area GSFINAL (CODE)
                                    155 	.area GSINIT  (CODE)
                                    156 	.globl __sdcc_gsinit_startup
                                    157 	.globl __sdcc_program_startup
                                    158 	.globl __start__stack
                                    159 	.globl __mcs51_genXINIT
                                    160 	.globl __mcs51_genXRAMCLEAR
                                    161 	.globl __mcs51_genRAMCLEAR
                                    162 	.area GSFINAL (CODE)
      0000A5 02 00 49         [24]  163 	ljmp	__sdcc_program_startup
                                    164 ;--------------------------------------------------------
                                    165 ; Home
                                    166 ;--------------------------------------------------------
                                    167 	.area HOME    (CODE)
                                    168 	.area HOME    (CODE)
      000049                        169 __sdcc_program_startup:
      000049 02 00 B6         [24]  170 	ljmp	_main
                                    171 ;	return from main will return to caller
                                    172 ;--------------------------------------------------------
                                    173 ; code
                                    174 ;--------------------------------------------------------
                                    175 	.area CSEG    (CODE)
                                    176 ;------------------------------------------------------------
                                    177 ;Allocation info for local variables in function 'add_sub'
                                    178 ;------------------------------------------------------------
                                    179 ;b             Allocated with name '_add_sub_PARM_2'
                                    180 ;a             Allocated to registers r7 
                                    181 ;------------------------------------------------------------
                                    182 ;	func_add_sub.c:1: char add_sub(char a, char b) {
                                    183 ;	-----------------------------------------
                                    184 ;	 function add_sub
                                    185 ;	-----------------------------------------
      0000A8                        186 _add_sub:
                           000007   187 	ar7 = 0x07
                           000006   188 	ar6 = 0x06
                           000005   189 	ar5 = 0x05
                           000004   190 	ar4 = 0x04
                           000003   191 	ar3 = 0x03
                           000002   192 	ar2 = 0x02
                           000001   193 	ar1 = 0x01
                           000000   194 	ar0 = 0x00
      0000A8 AF 82            [24]  195 	mov	r7, dpl
                                    196 ;	func_add_sub.c:2: return (a + b) ^ (a - b);
      0000AA E5 08            [12]  197 	mov	a,_add_sub_PARM_2
      0000AC 2F               [12]  198 	add	a, r7
      0000AD FE               [12]  199 	mov	r6,a
      0000AE EF               [12]  200 	mov	a,r7
      0000AF C3               [12]  201 	clr	c
      0000B0 95 08            [12]  202 	subb	a,_add_sub_PARM_2
      0000B2 6E               [12]  203 	xrl	a,r6
      0000B3 F5 82            [12]  204 	mov	dpl,a
                                    205 ;	func_add_sub.c:3: }
      0000B5 22               [24]  206 	ret
                                    207 ;------------------------------------------------------------
                                    208 ;Allocation info for local variables in function 'main'
                                    209 ;------------------------------------------------------------
                                    210 ;	func_add_sub.c:5: int main()
                                    211 ;	-----------------------------------------
                                    212 ;	 function main
                                    213 ;	-----------------------------------------
      0000B6                        214 _main:
                                    215 ;	func_add_sub.c:7: return 0;
      0000B6 90 00 00         [24]  216 	mov	dptr,#0x0000
                                    217 ;	func_add_sub.c:8: }
      0000B9 22               [24]  218 	ret
                                    219 	.area CSEG    (CODE)
                                    220 	.area CONST   (CODE)
                                    221 	.area XINIT   (CODE)
                                    222 	.area CABS    (ABS,CODE)
