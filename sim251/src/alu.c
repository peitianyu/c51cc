/*
 * alu.c — MCS-251 flag computation (from QEMU target/mcs251/helper.c).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "mcs251.h"

static inline int mcs251_parity8(uint32_t v)
{
    v ^= v >> 4;
    v &= 0xF;
    return (0x6996 >> v) & 1;
}

/* 8-bit add: res = a + b + cin (32-bit result). Sets CY/AC/OV/N/Z (+P). */
void mcs251_add8_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t cin, int up)
{
    uint32_t cy = (res >> 8) & 1;
    uint32_t ac = ((a & 0xF) + (b & 0xF) + cin) >> 4 & 1;
    uint32_t ov = (~(a ^ b) & (a ^ res)) >> 7 & 1;
    uint32_t n  = (res >> 7) & 1;
    uint32_t z  = ((res & 0xFF) == 0);

    c->psw  = (c->psw & ~(PSW_CY | PSW_AC | PSW_OV))
            | (cy << 7) | (ac << 6) | (ov << 2);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
    if (up)
        c->psw = (c->psw & ~PSW_P) | (mcs251_parity8(res & 0xFF) << 0);
}

/* 8-bit subtract: res = a - b - borrow. */
void mcs251_sub8_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t borrow, int up)
{
    uint32_t cy = (res >> 8) & 1;
    int32_t  tmp = (a & 0xF) - (b & 0xF) - borrow;
    uint32_t ac = (tmp < 0);
    uint32_t ov = ((a ^ b) & (a ^ res)) >> 7 & 1;
    uint32_t n  = (res >> 7) & 1;
    uint32_t z  = ((res & 0xFF) == 0);

    c->psw  = (c->psw & ~(PSW_CY | PSW_AC | PSW_OV))
            | (cy << 7) | (ac << 6) | (ov << 2);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
    if (up)
        c->psw = (c->psw & ~PSW_P) | (mcs251_parity8(res & 0xFF) << 0);
}

/* Logical / INC / DEC: only N and Z change. */
void mcs251_logic8_flags(MCS251 *c, uint32_t res)
{
    uint32_t n = (res >> 7) & 1;
    uint32_t z = ((res & 0xFF) == 0);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
}

/* Rotate / shift 8-bit: N/Z from res, CY from shifted-out bit. */
void mcs251_shift8_flags(MCS251 *c, uint32_t res, uint32_t carryout)
{
    uint32_t n = (res >> 7) & 1;
    uint32_t z = ((res & 0xFF) == 0);
    c->psw  = (c->psw & ~PSW_CY) | ((carryout & 1) << 7);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
}

/* 16-bit shift flags: N = bit15, Z = 16-bit zero. */
void mcs251_shiftw_flags(MCS251 *c, uint32_t res, uint32_t carryout)
{
    uint32_t n = (res >> 15) & 1;
    uint32_t z = ((res & 0xFFFF) == 0);
    c->psw  = (c->psw & ~PSW_CY) | ((carryout & 1) << 7);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
}

/* MUL/DIV 8-bit: CY=0, OV by argument. */
void mcs251_muldiv8_flags(MCS251 *c, uint32_t ov)
{
    c->psw = (c->psw & ~(PSW_CY | PSW_OV)) | ((ov & 1) << 2);
}

/* 16-bit add: res = a + b + cin; CY=bit16, OV=signed overflow, N=bit15. */
void mcs251_addw_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t cin)
{
    uint32_t cy = (res >> 16) & 1;
    uint32_t ov = (~(a ^ b) & (a ^ res)) >> 15 & 1;
    uint32_t n  = (res >> 15) & 1;
    uint32_t z  = ((res & 0xFFFF) == 0);
    c->psw  = (c->psw & ~(PSW_CY | PSW_OV)) | (cy << 7) | (ov << 2);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
}

void mcs251_subw_flags(MCS251 *c, uint32_t res, uint32_t a, uint32_t b,
                       uint32_t borrow)
{
    uint32_t cy = (res >> 16) & 1;
    uint32_t ov = ((a ^ b) & (a ^ res)) >> 15 & 1;
    uint32_t n  = (res >> 15) & 1;
    uint32_t z  = ((res & 0xFFFF) == 0);
    c->psw  = (c->psw & ~(PSW_CY | PSW_OV)) | (cy << 7) | (ov << 2);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
}

/* 16/32-bit logical: N=bit15, Z=low 16 zero. */
void mcs251_logicw_flags(MCS251 *c, uint32_t res, uint32_t size)
{
    (void)size;
    uint32_t n = (res >> 15) & 1;
    uint32_t z = ((res & 0xFFFF) == 0);
    c->psw1 = (c->psw1 & ~(PSW1_N | PSW1_Z)) | (n << 5) | (z << 1);
}

void mcs251_set_parity(MCS251 *c, uint32_t v)
{
    c->psw = (c->psw & ~PSW_P) | (mcs251_parity8(v & 0xFF) << 0);
}
