                                      1 ;--------------------------------------------------------
                                      2 ; File Created by SDCC : free open source ISO C Compiler
                                      3 ; Version 4.5.0 #15242 (MINGW64)
                                      4 ;--------------------------------------------------------
                                      5 	.module div_int
                                      6 	
                                      7 	.optsdcc -mmcs51 --model-small
                                      8 ;--------------------------------------------------------
                                      9 ; Public variables in this module
                                     10 ;--------------------------------------------------------
                                     11 	.globl _main
                                     12 	.globl _div_int
                                     13 	.globl _div_int_PARM_2
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
      000008                         33 _div_int_PARM_2:
      000008                         34 	.ds 2
                                     35 ;--------------------------------------------------------
                                     36 ; overlayable items in internal ram
                                     37 ;--------------------------------------------------------
                                     38 ;--------------------------------------------------------
                                     39 ; Stack segment in internal ram
                                     40 ;--------------------------------------------------------
                                     41 	.area SSEG
      00000C                         42 __start__stack:
      00000C                         43 	.ds	1
                                     44 
                                     45 ;--------------------------------------------------------
                                     46 ; indirectly addressable internal ram data
                                     47 ;--------------------------------------------------------
                                     48 	.area ISEG    (DATA)
                                     49 ;--------------------------------------------------------
                                     50 ; absolute internal ram data
                                     51 ;--------------------------------------------------------
                                     52 	.area IABS    (ABS,DATA)
                                     53 	.area IABS    (ABS,DATA)
                                     54 ;--------------------------------------------------------
                                     55 ; bit data
                                     56 ;--------------------------------------------------------
                                     57 	.area BSEG    (BIT)
                                     58 ;--------------------------------------------------------
                                     59 ; paged external ram data
                                     60 ;--------------------------------------------------------
                                     61 	.area PSEG    (PAG,XDATA)
                                     62 ;--------------------------------------------------------
                                     63 ; uninitialized external ram data
                                     64 ;--------------------------------------------------------
                                     65 	.area XSEG    (XDATA)
                                     66 ;--------------------------------------------------------
                                     67 ; absolute external ram data
                                     68 ;--------------------------------------------------------
                                     69 	.area XABS    (ABS,XDATA)
                                     70 ;--------------------------------------------------------
                                     71 ; initialized external ram data
                                     72 ;--------------------------------------------------------
                                     73 	.area XISEG   (XDATA)
                                     74 	.area HOME    (CODE)
                                     75 	.area GSINIT0 (CODE)
                                     76 	.area GSINIT1 (CODE)
                                     77 	.area GSINIT2 (CODE)
                                     78 	.area GSINIT3 (CODE)
                                     79 	.area GSINIT4 (CODE)
                                     80 	.area GSINIT5 (CODE)
                                     81 	.area GSINIT  (CODE)
                                     82 	.area GSFINAL (CODE)
                                     83 	.area CSEG    (CODE)
                                     84 ;--------------------------------------------------------
                                     85 ; interrupt vector
                                     86 ;--------------------------------------------------------
                                     87 	.area HOME    (CODE)
      000000                         88 __interrupt_vect:
      000000 02 00 4C         [24]   89 	ljmp	__sdcc_gsinit_startup
                                     90 ; restartable atomic support routines
      000003                         91 	.ds	5
      000008                         92 sdcc_atomic_exchange_rollback_start::
      000008 00               [12]   93 	nop
      000009 00               [12]   94 	nop
      00000A                         95 sdcc_atomic_exchange_pdata_impl:
      00000A E2               [24]   96 	movx	a, @r0
      00000B FB               [12]   97 	mov	r3, a
      00000C EA               [12]   98 	mov	a, r2
      00000D F2               [24]   99 	movx	@r0, a
      00000E 80 2C            [24]  100 	sjmp	sdcc_atomic_exchange_exit
      000010 00               [12]  101 	nop
      000011 00               [12]  102 	nop
      000012                        103 sdcc_atomic_exchange_xdata_impl:
      000012 E0               [24]  104 	movx	a, @dptr
      000013 FB               [12]  105 	mov	r3, a
      000014 EA               [12]  106 	mov	a, r2
      000015 F0               [24]  107 	movx	@dptr, a
      000016 80 24            [24]  108 	sjmp	sdcc_atomic_exchange_exit
      000018                        109 sdcc_atomic_compare_exchange_idata_impl:
      000018 E6               [12]  110 	mov	a, @r0
      000019 B5 02 02         [24]  111 	cjne	a, ar2, .+#5
      00001C EB               [12]  112 	mov	a, r3
      00001D F6               [12]  113 	mov	@r0, a
      00001E 22               [24]  114 	ret
      00001F 00               [12]  115 	nop
      000020                        116 sdcc_atomic_compare_exchange_pdata_impl:
      000020 E2               [24]  117 	movx	a, @r0
      000021 B5 02 02         [24]  118 	cjne	a, ar2, .+#5
      000024 EB               [12]  119 	mov	a, r3
      000025 F2               [24]  120 	movx	@r0, a
      000026 22               [24]  121 	ret
      000027 00               [12]  122 	nop
      000028                        123 sdcc_atomic_compare_exchange_xdata_impl:
      000028 E0               [24]  124 	movx	a, @dptr
      000029 B5 02 02         [24]  125 	cjne	a, ar2, .+#5
      00002C EB               [12]  126 	mov	a, r3
      00002D F0               [24]  127 	movx	@dptr, a
      00002E 22               [24]  128 	ret
      00002F                        129 sdcc_atomic_exchange_rollback_end::
                                    130 
      00002F                        131 sdcc_atomic_exchange_gptr_impl::
      00002F 30 F6 E0         [24]  132 	jnb	b.6, sdcc_atomic_exchange_xdata_impl
      000032 A8 82            [24]  133 	mov	r0, dpl
      000034 20 F5 D3         [24]  134 	jb	b.5, sdcc_atomic_exchange_pdata_impl
      000037                        135 sdcc_atomic_exchange_idata_impl:
      000037 EA               [12]  136 	mov	a, r2
      000038 C6               [12]  137 	xch	a, @r0
      000039 F5 82            [12]  138 	mov	dpl, a
      00003B 22               [24]  139 	ret
      00003C                        140 sdcc_atomic_exchange_exit:
      00003C 8B 82            [24]  141 	mov	dpl, r3
      00003E 22               [24]  142 	ret
      00003F                        143 sdcc_atomic_compare_exchange_gptr_impl::
      00003F 30 F6 E6         [24]  144 	jnb	b.6, sdcc_atomic_compare_exchange_xdata_impl
      000042 A8 82            [24]  145 	mov	r0, dpl
      000044 20 F5 D9         [24]  146 	jb	b.5, sdcc_atomic_compare_exchange_pdata_impl
      000047 80 CF            [24]  147 	sjmp	sdcc_atomic_compare_exchange_idata_impl
                                    148 ;--------------------------------------------------------
                                    149 ; global & static initialisations
                                    150 ;--------------------------------------------------------
                                    151 	.area HOME    (CODE)
                                    152 	.area GSINIT  (CODE)
                                    153 	.area GSFINAL (CODE)
                                    154 	.area GSINIT  (CODE)
                                    155 	.globl __sdcc_gsinit_startup
                                    156 	.globl __sdcc_program_startup
                                    157 	.globl __start__stack
                                    158 	.globl __mcs51_genXINIT
                                    159 	.globl __mcs51_genXRAMCLEAR
                                    160 	.globl __mcs51_genRAMCLEAR
                                    161 	.area GSFINAL (CODE)
      0000A5 02 00 49         [24]  162 	ljmp	__sdcc_program_startup
                                    163 ;--------------------------------------------------------
                                    164 ; Home
                                    165 ;--------------------------------------------------------
                                    166 	.area HOME    (CODE)
                                    167 	.area HOME    (CODE)
      000049                        168 __sdcc_program_startup:
      000049 02 00 B1         [24]  169 	ljmp	_main
                                    170 ;	return from main will return to caller
                                    171 ;--------------------------------------------------------
                                    172 ; code
                                    173 ;--------------------------------------------------------
                                    174 	.area CSEG    (CODE)
                                    175 ;------------------------------------------------------------
                                    176 ;Allocation info for local variables in function 'div_int'
                                    177 ;------------------------------------------------------------
                                    178 ;b             Allocated with name '_div_int_PARM_2'
                                    179 ;a             Allocated to registers r6 r7 
                                    180 ;------------------------------------------------------------
                                    181 ;	div_int.c:1: int div_int(int a, int b) { return a / b; }
                                    182 ;	-----------------------------------------
                                    183 ;	 function div_int
                                    184 ;	-----------------------------------------
      0000A8                        185 _div_int:
                           000007   186 	ar7 = 0x07
                           000006   187 	ar6 = 0x06
                           000005   188 	ar5 = 0x05
                           000004   189 	ar4 = 0x04
                           000003   190 	ar3 = 0x03
                           000002   191 	ar2 = 0x02
                           000001   192 	ar1 = 0x01
                           000000   193 	ar0 = 0x00
      0000A8 85 08 0A         [24]  194 	mov	__divsint_PARM_2,_div_int_PARM_2
      0000AB 85 09 0B         [24]  195 	mov	(__divsint_PARM_2 + 1),(_div_int_PARM_2 + 1)
      0000AE 02 00 DE         [24]  196 	ljmp	__divsint
                                    197 ;------------------------------------------------------------
                                    198 ;Allocation info for local variables in function 'main'
                                    199 ;------------------------------------------------------------
                                    200 ;	div_int.c:3: int main()
                                    201 ;	-----------------------------------------
                                    202 ;	 function main
                                    203 ;	-----------------------------------------
      0000B1                        204 _main:
                                    205 ;	div_int.c:5: return 0;
      0000B1 90 00 00         [24]  206 	mov	dptr,#0x0000
                                    207 ;	div_int.c:6: }
      0000B4 22               [24]  208 	ret
                                    209 	.area CSEG    (CODE)
                                    210 	.area CONST   (CODE)
                                    211 	.area XINIT   (CODE)
                                    212 	.area CABS    (ABS,CODE)
