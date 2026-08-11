/* STC32G P7 running light - acceptance firmware for the mcs251 emulator.
 *
 * P7 (SFR 0xF8 on STC32G12K128) is bit-driven low-active (0 = LED on).
 * The visible 8-value cycle is fe fd fb f7 ef df bf 7f, then it wraps.
 * NOTE: STC32G SFR layout differs from classic 8051 — P6=0xE8, P7=0xF8
 * (official STC32G.H).  Using P7=0xE8 would alias P6 and silently break
 * the demo on real silicon.
 *
 * Built on the fly by `make stc32g` with tcc_c251 (the .hex output is
 * git-ignored, only this source is tracked).
 */
sfr P7 = 0xF8;

void delay_ms(unsigned int ms)
{
	unsigned int i;
	do {
		i = 60000;
		while (--i);
	} while (--ms);
}

void main(void)
{
	unsigned char v = 0xfe;
	for (;;) {
		P7 = v;
		delay_ms(1);
		v = (unsigned char)((v << 1) | 1);
		if (v == 0xff)
			v = 0xfe;
	}
}
