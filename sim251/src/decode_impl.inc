/*
 * decode_impl.inc — decoder implementations (included by cpu.c).
 * Direct translation of QEMU translate_impl.c.inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ------------------------------------------------------------------ */
/* op_from_hi (Table A-9)                                              */
/* ------------------------------------------------------------------ */
static int op_from_hi(int hi)
{
    /* MCS-251 source mode (Keil C251, xsmall) regop2 op map — verified
     * against tcc_c251's own emitters (c251-hex.c, reverse-engineered
     * byte-for-byte from Keil hex):
     *   0x2D ADD WRj, 0x4D ORL WRj, 0x5D ANL WRj, 0x6D XRL WRj,
     *   0x8C/0x8D DIV Rm/WRj, 0x9D SUB WRj, 0xAD MUL WRj, 0xBD CMP WRj. */
    switch (hi) {
    case 0x2: return OP_ADD;
    case 0x3: return OP_SLL;
    case 0x4: return OP_ORL;
    case 0x5: return OP_ANL;
    case 0x6: return OP_XRL;
    case 0x7: return OP_MOV;
    case 0x8: return OP_DIV;
    case 0x9: return OP_SUB;
    case 0xA: return OP_MUL;
    case 0xB: return OP_CMP;
    case 0xD: return OP_XRL;
    default:  return -1;
    }
}

/* ------------------------------------------------------------------ */
/* 8-bit add/sub helpers for reg,op2 (up=0: no parity update)          */
/* ------------------------------------------------------------------ */
static void add8(MCS251 *c, uint8_t rd, uint32_t a, uint32_t b, uint32_t cin)
{
    uint32_t res = a + b + cin;
    mcs251_add8_flags(c, res, a, b, cin, 0);
    mcs251_st_reg8(c, rd, res & 0xFF);
}

/* rd<0 = CMP (只设标志, 不存储)。注意: rd 必须是 int! 若为 uint8_t,
 * CMP 哨兵 -1 会变成 255, st_reg8(255) 越界写 c->rf[255] → 溢出到
 * c->iram[0xBF] (栈区), 静默破坏返回地址 → RET 逃逸 (Keil 19 根因)。 */
static void sub8(MCS251 *c, int rd, uint32_t a, uint32_t b, uint32_t borrow)
{
    uint32_t res = a - b - borrow;
    mcs251_sub8_flags(c, res, a, b, borrow, 0);
    if (rd >= 0)
        mcs251_st_reg8(c, rd, res & 0xFF);
}

/* ------------------------------------------------------------------ */
/* regop2: Rmd,Rms (byte)                                              */
/* ------------------------------------------------------------------ */
static void regop2_byte(MCS251 *c, int op, int rd, int rs)
{
    if (op == OP_MOV) {
        mcs251_st_reg8(c, rd, mcs251_ld_reg8(c, rs));
        return;
    }
    uint8_t a = mcs251_ld_reg8(c, rd);
    uint8_t b = mcs251_ld_reg8(c, rs);
    switch (op) {
    case OP_ADD: add8(c, rd, a, b, 0); break;
    case OP_SUB: sub8(c, rd, a, b, 0); break;
    case OP_CMP: sub8(c, -1, a, b, 0); break;   /* rd=-1: no store */
    case OP_ORL: {
        uint32_t r = a | b; mcs251_logic8_flags(c, r);
        mcs251_st_reg8(c, rd, r & 0xFF); break; }
    case OP_ANL: {
        uint32_t r = a & b; mcs251_logic8_flags(c, r);
        mcs251_st_reg8(c, rd, r & 0xFF); break; }
    case OP_XRL: {
        uint32_t r = a ^ b; mcs251_logic8_flags(c, r);
        mcs251_st_reg8(c, rd, r & 0xFF); break; }
    case OP_SLL: {  /* SLL Rm: shift left 1 */
        uint32_t r = (a << 1) & 0xFF;
        mcs251_shift8_flags(c, r, (a >> 7) & 1);
        mcs251_st_reg8(c, rd, r); break; }
    case OP_SRL: {  /* SRL Rm: shift right 1 */
        uint32_t r = a >> 1;
        mcs251_shift8_flags(c, r, a & 1);
        mcs251_st_reg8(c, rd, r); break; }
    case OP_MUL: {
        uint16_t res = (uint16_t)(a * b);
        /* C251 MUL Rm,Rn: 16 位结果 → Rm 所在 WR 对 (偶对齐 pair = rd & ~1),
           低字节 → 奇数成员, 高字节 → 偶数成员 (与 MUL AB 一致: A=R11 低,
           B=R10 高; Keil golden_func nested_a x*2: MUL R11,R7; RET 返回
           R11 = 低字节 = 结果)。 */
        int pair = rd & ~1;
        mcs251_st_reg8(c, pair + 1, res & 0xFF);
        mcs251_st_reg8(c, pair, (res >> 8) & 0xFF);
        mcs251_muldiv8_flags(c, res > 0xFF);
        mcs251_logic8_flags(c, res);
        break; }
    case OP_DIV: {
        uint8_t q = 0, r = 0, ov = 0;
        if (b != 0) { q = a / b; r = a % b; } else { ov = 1; }
        /* C251 8 位 DIV Rm,Rn: 商→编号大的寄存器, 余数→编号小的。
           (与 DIV AB 一致: A=R11 > B=R10 → 商→A, 余→B; Keil REF 03
           main 验证: DIV R7,R6 / DIV R6,R7 都取 R7 作商 → 商→大)。
           ★ 不能用"余→被除数 rd, 商→rd±1" — Keil 唤醒次数会输出
           101 而非 001 (被除数/除数谁大谁小不定, rd±1 只是 DR 对)。 */
        if (rd > rs) {
            mcs251_st_reg8(c, rd, q);
            mcs251_st_reg8(c, rs, r);
        } else {
            mcs251_st_reg8(c, rs, q);
            mcs251_st_reg8(c, rd, r);
        }
        mcs251_muldiv8_flags(c, ov);
        mcs251_logic8_flags(c, q);
        break; }
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* regop2: WRjd,WRjs (word)                                            */
/* ------------------------------------------------------------------ */
static void regop2_word(MCS251 *c, int op, int rd, int rs)
{
    if (op == OP_MOV) {
        mcs251_st_wrj16(c, rd, mcs251_ld_wrj16(c, rs));
        return;
    }
    uint16_t a = mcs251_ld_wrj16(c, rd);
    uint16_t b = mcs251_ld_wrj16(c, rs);
    switch (op) {
    case OP_ADD: {
        uint32_t r = a + b;
        mcs251_addw_flags(c, r, a, b, 0);
        mcs251_st_wrj16(c, rd, r & 0xFFFF);
        break; }
    case OP_SUB: {
        uint32_t r = a - b;
        mcs251_subw_flags(c, r, a, b, 0);
        mcs251_st_wrj16(c, rd, r & 0xFFFF);
        break; }
    case OP_CMP: {
        uint32_t r = a - b;
        mcs251_subw_flags(c, r, a, b, 0);
        break; }
    case OP_ORL: {
        uint32_t r = a | b; mcs251_logicw_flags(c, r, 2);
        mcs251_st_wrj16(c, rd, r & 0xFFFF); break; }
    case OP_ANL: {
        uint32_t r = a & b; mcs251_logicw_flags(c, r, 2);
        mcs251_st_wrj16(c, rd, r & 0xFFFF); break; }
    case OP_XRL: {
        uint32_t r = a ^ b; mcs251_logicw_flags(c, r, 2);
        mcs251_st_wrj16(c, rd, r & 0xFFFF); break; }
    case OP_SLL: {
        uint32_t r = (a << 1) & 0xFFFF;
        mcs251_shiftw_flags(c, r, (a >> 15) & 1);
        mcs251_st_wrj16(c, rd, r); break; }
    case OP_SRL: {
        uint32_t r = a >> 1;
        mcs251_shiftw_flags(c, r, a & 1);
        mcs251_st_wrj16(c, rd, r); break; }
    case OP_MUL: {
        uint32_t res = (uint32_t)a * b;
        /* C251 MUL WRj,WRj: 32 位结果 → 目标 WRj 的 DR 对 (partner = rd ^ 2),
           低字 → 目标 WRj (rd), 高字 → partner。Keil golden_compute:
           MUL WR6,WR4; XRL WR4,WR4 (清高字); MOV [..],WR6 (结果读低字 WR6)。 */
        mcs251_st_wrj16(c, rd, res & 0xFFFF);
        mcs251_st_wrj16(c, rd ^ 2, (res >> 16) & 0xFFFF);
        mcs251_muldiv8_flags(c, res > 0xFFFF);
        mcs251_logicw_flags(c, res, 2);
        break; }
    case OP_DIV: {
        uint16_t q = 0, r = 0, ov = 0;
        if (b != 0) { q = a / b; r = a % b; } else { ov = 1; }
        /* C251 DIV WRj,WRj: 商→目标 WRj (rd), 余数→ DR 对另一侧。
           Keil golden_compute: DIV WR6,WR4; MOV [..],WR6 (商读 WR6);
           DIV WR4,WR6; MOV [..],WR4 (商读 WR4)。原实现余数→rd 反了
           (u16 无符号除法 suite 06 商错; ?C?LIB_CODE 符号 helper 也
           依赖商→WR6)。 */
        mcs251_st_wrj16(c, rd, q);
        mcs251_st_wrj16(c, (rd & 2) == 0 ? rd + 2 : rd - 2, r);
        mcs251_muldiv8_flags(c, ov);
        mcs251_logicw_flags(c, q, 2);
        break; }
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* regop2: DRkd,DRks (dword)                                           */
/* ------------------------------------------------------------------ */
static void regop2_dword(MCS251 *c, int op, int rd, int rs)
{
    if (op == OP_MOV) {
        mcs251_st_drk32(c, rd, mcs251_ld_drk32(c, rs));
        return;
    }
    uint32_t a = mcs251_ld_drk32(c, rd);
    uint32_t b = mcs251_ld_drk32(c, rs);
    switch (op) {
    case OP_ADD: {
        uint32_t r = a + b;
        mcs251_addw_flags(c, r, a, b, 0);
        mcs251_st_drk32(c, rd, r);
        break; }
    case OP_SUB: {
        uint32_t r = a - b;
        mcs251_subw_flags(c, r, a, b, 0);
        mcs251_st_drk32(c, rd, r);
        break; }
    case OP_CMP: {
        uint32_t r = a - b;
        mcs251_subw_flags(c, r, a, b, 0);
        break; }
    case OP_ORL: {
        uint32_t r = a | b; mcs251_logicw_flags(c, r, 4);
        mcs251_st_drk32(c, rd, r); break; }
    case OP_ANL: {
        uint32_t r = a & b; mcs251_logicw_flags(c, r, 4);
        mcs251_st_drk32(c, rd, r); break; }
    case OP_XRL: {
        uint32_t r = a ^ b; mcs251_logicw_flags(c, r, 4);
        mcs251_st_drk32(c, rd, r); break; }
    case OP_SLL: {
        uint32_t r = (a << 1) & 0xFFFFFFFFu;
        mcs251_shiftw_flags(c, r, (a >> 31) & 1);
        mcs251_st_drk32(c, rd, r); break; }
    case OP_SRL: {
        uint32_t r = a >> 1;
        mcs251_shiftw_flags(c, r, a & 1);
        mcs251_st_drk32(c, rd, r); break; }
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* regop2 with indirect @WRj/@DRk source. far=1 → @DRk (可路由到 XFR 窗口). */
/* ------------------------------------------------------------------ */
static void regop2_ind(MCS251 *c, int op, int rd, int size, uint32_t addr, int far)
{
    uint8_t  (*ld8)(MCS251 *, uint32_t)   = far ? mcs251_ld_far8   : mcs251_ld_mem8;
    uint16_t (*ld16)(MCS251 *, uint32_t)  = far ? mcs251_ld_far16  : mcs251_ld_mem16;
    uint32_t (*ld32)(MCS251 *, uint32_t)  = far ? mcs251_ld_far32  : mcs251_ld_mem32;
    if (op == OP_MOV) {
        if (size == 1)      mcs251_st_reg8(c, rd, ld8(c, addr));
        else if (size == 2) mcs251_st_wrj16(c, rd, ld16(c, addr));
        else                mcs251_st_drk32(c, rd, ld32(c, addr));
        return;
    }
    if (size == 1) {
        uint8_t a = mcs251_ld_reg8(c, rd);
        uint8_t b = ld8(c, addr);
        switch (op) {
        case OP_ADD: add8(c, rd, a, b, 0); break;
        case OP_SUB: sub8(c, rd, a, b, 0); break;
        case OP_CMP: sub8(c, -1, a, b, 0); break;
        case OP_ORL: { uint32_t r=a|b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,rd,r&0xFF); break; }
        case OP_ANL: { uint32_t r=a&b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,rd,r&0xFF); break; }
        case OP_XRL: { uint32_t r=a^b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,rd,r&0xFF); break; }
        default: break;
        }
    } else if (size == 2) {
        uint16_t a = mcs251_ld_wrj16(c, rd);
        uint16_t b = ld16(c, addr);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+b; mcs251_addw_flags(c,r,a,b,0);
                     mcs251_st_wrj16(c,rd,r&0xFFFF); break;
        case OP_SUB: r=a-b; mcs251_subw_flags(c,r,a,b,0);
                     mcs251_st_wrj16(c,rd,r&0xFFFF); break;
        case OP_CMP: r=a-b; mcs251_subw_flags(c,r,a,b,0); break;
        case OP_ORL: r=a|b; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,rd,r&0xFFFF); break;
        case OP_ANL: r=a&b; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,rd,r&0xFFFF); break;
        case OP_XRL: r=a^b; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,rd,r&0xFFFF); break;
        default: break;
        }
    } else {
        uint32_t a = mcs251_ld_drk32(c, rd);
        uint32_t b = ld32(c, addr);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+b; mcs251_addw_flags(c,r,a,b,0);
                     mcs251_st_drk32(c,rd,r); break;
        case OP_SUB: r=a-b; mcs251_subw_flags(c,r,a,b,0);
                     mcs251_st_drk32(c,rd,r); break;
        case OP_CMP: r=a-b; mcs251_subw_flags(c,r,a,b,0); break;
        case OP_ORL: r=a|b; mcs251_logicw_flags(c,r,4);
                     mcs251_st_drk32(c,rd,r); break;
        case OP_ANL: r=a&b; mcs251_logicw_flags(c,r,4);
                     mcs251_st_drk32(c,rd,r); break;
        case OP_XRL: r=a^b; mcs251_logicw_flags(c,r,4);
                     mcs251_st_drk32(c,rd,r); break;
        default: break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* regop2 generic (Table A-8 byte1)                                    */
/* ------------------------------------------------------------------ */
static void regop2_generic(MCS251 *c, int op, uint8_t b1)
{
    int idx = b1 >> 4;
    int kind = b1 & 0x0F;

    switch (kind) {
    case 0x0: { /* Rm,#data */
        int m = idx;
        uint8_t data = fetch8(c);
        if (op == OP_MOV) { mcs251_st_reg8(c, m, data); return; }
        uint8_t a = mcs251_ld_reg8(c, m);
        switch (op) {
        case OP_ADD: add8(c, m, a, data, 0); break;
        case OP_SUB: sub8(c, m, a, data, 0); break;
        case OP_CMP: sub8(c, -1, a, data, 0); break;
        case OP_ORL: { uint32_t r=a|data; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        case OP_ANL: { uint32_t r=a&data; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        case OP_XRL: { uint32_t r=a^data; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        default: break;
        }
        break; }
    case 0x4: { /* WRj,#data16 */
        int j = idx * 2;
        uint16_t data = fetch16be(c);
        if (op == OP_MOV) { mcs251_st_wrj16(c, j, data); return; }
        uint16_t a = mcs251_ld_wrj16(c, j);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+data; mcs251_addw_flags(c,r,a,data,0);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_SUB: r=a-data; mcs251_subw_flags(c,r,a,data,0);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_CMP: r=a-data; mcs251_subw_flags(c,r,a,data,0); break;
        case OP_ORL: r=a|data; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_ANL: r=a&data; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_XRL: r=a^data; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        default: break;
        }
        break; }
    case 0xC: case 0x8: { /* DRk,#data16 (0data16 / 1data16) */
        int k = idx * 4;
        uint16_t data = fetch16be(c);
        if (op == OP_MOV) { mcs251_st_drk32(c, k, data); return; }
        if (op == OP_CMP) {
            uint32_t a = mcs251_ld_drk32(c, k);
            uint32_t r = a - data;
            mcs251_subw_flags(c, r, a, data, 0);
        }
        break; }
    case 0x1: { /* Rm,dir8 */
        int m = idx;
        uint8_t dir = fetch8(c);
        uint8_t b = mcs251_ld_direct8(c, dir);
        if (op == OP_MOV) { mcs251_st_reg8(c, m, b); return; }
        uint8_t a = mcs251_ld_reg8(c, m);
        switch (op) {
        case OP_ADD: add8(c, m, a, b, 0); break;
        case OP_SUB: sub8(c, m, a, b, 0); break;
        case OP_CMP: sub8(c, -1, a, b, 0); break;
        case OP_ORL: { uint32_t r=a|b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        case OP_ANL: { uint32_t r=a&b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        case OP_XRL: { uint32_t r=a^b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        default: break;
        }
        break; }
    case 0x5: { /* WRj,#data8 (Keil: MOV WRj,#imm8) */
        int j = idx * 2;
        uint8_t data = fetch8(c);
        if (op == OP_MOV) { mcs251_st_wrj16(c, j, data); return; }
        uint16_t a = mcs251_ld_wrj16(c, j);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+data; mcs251_addw_flags(c,r,a,data,0);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_SUB: r=a-data; mcs251_subw_flags(c,r,a,data,0);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_CMP: r=a-data; mcs251_subw_flags(c,r,a,data,0); break;
        case OP_ORL: r=a|data; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_ANL: r=a&data; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_XRL: r=a^data; mcs251_logicw_flags(c,r,2);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        default: break;
        }
        break; }
    case 0x2: { /* Rm,@Ri (byte) */
        int m = idx;
        uint8_t b2 = fetch8(c);
        int i = b2 & 1;
        regop2_ind(c, op, m, 1, mcs251_ld_reg8(c, i), 0);
        break; }
    case 0x6: { /* WRj,@Ri (word) */
        int j = idx * 2;
        uint8_t b2 = fetch8(c);
        int i = b2 & 1;
        regop2_ind(c, op, j, 2, mcs251_ld_reg8(c, i), 0);
        break; }
    case 0xA: { /* WRj,@WRj (word) */
        int j = idx * 2;
        uint8_t b2 = fetch8(c);
        int ws = (b2 >> 4) * 2;
        regop2_ind(c, op, j, 2, mcs251_ld_wrj16(c, ws), 0);
        break; }
    case 0xE: { /* DRk,@WRj (dword) */
        int k = idx * 4;
        uint8_t b2 = fetch8(c);
        int ws = (b2 >> 4) * 2;
        regop2_ind(c, op, k, 4, mcs251_ld_wrj16(c, ws), 0);
        break; }
    case 0x9: { /* Rm,@WRj */
        int j = idx * 2;
        uint8_t b2 = fetch8(c);
        int m = b2 >> 4;
        regop2_ind(c, op, m, 1, mcs251_ld_wrj16(c, j), 0);
        break; }
    case 0xB: { /* Rm,@DRk (far: 路由 XFR/code) */
        int k = idx * 4;
        uint8_t b2 = fetch8(c);
        int m = b2 >> 4;
        fprintf(stderr, "[DEC-B] pc=%04X b1=%02X b2=%02X idx=%d k=%d m=%d op=%d cy=%llu\n",
                (unsigned)(c->pc - 3), b1, b2, idx, k, m, op,
                (unsigned long long)c->cycles);
        regop2_ind(c, op, m, 1, mcs251_ld_drk32(c, k) & 0xFFFFFF, 1);
        break; }
    case 0x3: { /* Rm,dir16 */
        int m = idx;
        uint16_t dir = fetch16be(c);
        uint8_t b = mcs251_ld_mem8(c, dir);
        if (op == OP_MOV) { mcs251_st_reg8(c, m, b); return; }
        uint8_t a = mcs251_ld_reg8(c, m);
        switch (op) {
        case OP_ADD: add8(c, m, a, b, 0); break;
        case OP_SUB: sub8(c, m, a, b, 0); break;
        case OP_CMP: sub8(c, -1, a, b, 0); break;
        case OP_ORL: { uint32_t r=a|b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        case OP_ANL: { uint32_t r=a&b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        case OP_XRL: { uint32_t r=a^b; mcs251_logic8_flags(c,r);
                       mcs251_st_reg8(c,m,r&0xFF); break; }
        default: break;
        }
        break; }
    case 0x7: { /* WRj,dir16 */
        int j = idx * 2;
        uint16_t dir = fetch16be(c);
        uint16_t b = mcs251_ld_mem16(c, dir);
        if (op == OP_MOV) { mcs251_st_wrj16(c, j, b); return; }
        uint16_t a = mcs251_ld_wrj16(c, j);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+b; mcs251_addw_flags(c,r,a,b,0);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_SUB: r=a-b; mcs251_subw_flags(c,r,a,b,0);
                     mcs251_st_wrj16(c,j,r&0xFFFF); break;
        case OP_CMP: r=a-b; mcs251_subw_flags(c,r,a,b,0); break;
        default: break;
        }
        break; }
    case 0xD: { /* DRk,dir8 (32-bit direct from IRAM) */
        int k = idx * 4;
        uint8_t dir = fetch8(c);
        uint32_t b = mcs251_ld_iram32(c, dir);
        if (op == OP_MOV) { mcs251_st_drk32(c, k, b); return; }
        uint32_t a = mcs251_ld_drk32(c, k);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+b; mcs251_addw_flags(c,r,a,b,0);
                     mcs251_st_drk32(c,k,r); break;
        case OP_SUB: r=a-b; mcs251_subw_flags(c,r,a,b,0);
                     mcs251_st_drk32(c,k,r); break;
        case OP_CMP: r=a-b; mcs251_subw_flags(c,r,a,b,0); break;
        default: break;
        }
        break; }
    case 0xF: { /* DRk,dir16 (32-bit direct from dir16) */
        int k = idx * 4;
        uint16_t dir = fetch16be(c);
        uint32_t b = mcs251_ld_mem32(c, dir);
        if (op == OP_MOV) { mcs251_st_drk32(c, k, b); return; }
        uint32_t a = mcs251_ld_drk32(c, k);
        uint32_t r;
        switch (op) {
        case OP_ADD: r=a+b; mcs251_addw_flags(c,r,a,b,0);
                     mcs251_st_drk32(c,k,r); break;
        case OP_SUB: r=a-b; mcs251_subw_flags(c,r,a,b,0);
                     mcs251_st_drk32(c,k,r); break;
        case OP_CMP: r=a-b; mcs251_subw_flags(c,r,a,b,0); break;
        case OP_ORL: r=a|b; mcs251_logicw_flags(c,r,4);
                     mcs251_st_drk32(c,k,r); break;
        case OP_ANL: r=a&b; mcs251_logicw_flags(c,r,4);
                     mcs251_st_drk32(c,k,r); break;
        case OP_XRL: r=a^b; mcs251_logicw_flags(c,r,4);
                     mcs251_st_drk32(c,k,r); break;
        default: break;
        }
        break; }
    default:
        break;
    }
}

/* reg,op2 dispatch: op0 low nibble C/D/E/F, op from high nibble.
 * Source-mode register file (R0-R15): byte ops use the raw 4-bit field,
 * word ops mask &7 (WR0-WR14), dword ops mask &3 (DR0-DR12).
 * 0x7E (MOV reg,op2) is the exception: its field indexes the full
 * 64-byte register file so DR56/DR60 (DPTR/SPX aliases) stay reachable. */
static void decode_regop2(MCS251 *c, uint8_t op0)
{
    uint8_t b1 = fetch8(c);
    int op = op_from_hi(op0 >> 4);
    int lo = op0 & 0x0F;
    if (op < 0)
        return;
    switch (lo) {
    case 0xC: regop2_byte(c, op, b1 >> 4, b1 & 0xF); break;   /* Rm,Rm */
    case 0xD: regop2_word(c, op, (b1 >> 4) * 2, (b1 & 0xF) * 2); break;  /* WRj,WRj (4 位字段 = j/2, WR0-WR30) */
    case 0xE: regop2_generic(c, op, b1); break;   /* reg,op2 — 变长 (含 0x7E MOV) */
    case 0xF: regop2_dword(c, op, (b1 >> 4) * 4, (b1 & 0xF) * 4); break;  /* DRk,DRk (4 位字段 = k/4, DR0-DR60) */
    default: break;
    }
}

/* ------------------------------------------------------------------ */
/* MOVZ / MOVS (sign/zero extend byte -> word)                         */
/* ------------------------------------------------------------------ */
static void do_movz(MCS251 *c, int sign)
{
    uint8_t b1 = fetch8(c);
    int j = (b1 >> 4) * 2;
    int m = b1 & 0xF;
    uint8_t t = mcs251_ld_reg8(c, m);
    uint16_t v = sign ? (uint16_t)(int16_t)(int8_t)t : (uint16_t)t;
    mcs251_st_wrj16(c, j, v);
}

/* INC/DEC Rm/WRj/DRk,#short (0x0B/0x1B, Keil).  enc 低半字节:
 *   bits 1-0 = 增量 (0→1, 1→2, 2→4); bit2 = word; bit3 = dword.
 *   enc&0x0C==0x08 → MOV WRn,@WRj (0x08) / MOV WRn,@DRk (0x0A), 3 字节。 */
static void inc_dec_short(MCS251 *c, int dec)
{
    uint8_t b1 = fetch8(c);
    int ss = b1 & 3;
    int sel = (b1 >> 2) & 3;
    int shortv = (ss == 0) ? 1 : (ss == 1) ? 2 : 4;
    int idx = b1 >> 4;
    if (sel == 0) {
        uint8_t t = mcs251_ld_reg8(c, idx);
        uint8_t res = dec ? (uint8_t)(t - shortv) : (uint8_t)(t + shortv);
        mcs251_st_reg8(c, idx, res);
        mcs251_logic8_flags(c, res);
    } else if (sel == 1) {
        uint16_t t = mcs251_ld_wrj16(c, idx * 2);
        uint16_t res = dec ? (uint16_t)(t - shortv) : (uint16_t)(t + shortv);
        mcs251_st_wrj16(c, idx * 2, res);
        mcs251_logicw_flags(c, res, 2);
    } else if (sel == 2) {
        /* 0x0B (dec=0): MOV WRn,@WRj (0x08) / MOV WRn,@DRk (0x0A) — 读。
           0x1B (dec=1): MOV @WRj,WRn (0x18) / MOV @DRk,WRn (0x1A) — 写。
           (Keil golden_ptr: 16 位指针解引用写 *p=u16 → 1B 0A 30 =
           MOV @DR0,WR6; 原实现 dec 被忽略 → 写被误判成读, *p=100 失效。) */
        uint8_t b2 = fetch8(c);
        uint32_t addr;
        if (b1 & 2) {  /* @DRk (far: 路由 XFR/code) */
            addr = mcs251_ld_drk32(c, idx * 4) & 0xFFFFFF;
            if (dec)
                mcs251_st_far16(c, addr, mcs251_ld_wrj16(c, (b2 >> 4) * 2));
            else
                mcs251_st_wrj16(c, (b2 >> 4) * 2, mcs251_ld_far16(c, addr));
        } else {       /* @WRj */
            addr = mcs251_ld_wrj16(c, idx * 2) & 0xFFFF;
            if (dec)
                mcs251_st_mem16(c, addr, mcs251_ld_wrj16(c, (b2 >> 4) * 2));
            else
                mcs251_st_wrj16(c, (b2 >> 4) * 2, mcs251_ld_mem16(c, addr));
        }
    } else {
        uint32_t t = mcs251_ld_drk32(c, idx * 4);
        uint32_t res = dec ? (t - shortv) : (t + shortv);
        mcs251_st_drk32(c, idx * 4, res);
        mcs251_logicw_flags(c, res, 4);
    }
}

/* SRA/SRL/SLL Rm/WRj/DRk (0x0E/0x1E/0x3E, Keil 单操作数).
 * enc 高半字节 = 寄存器; 低半字节 0=byte 4=word C=dword. */
static void shift_single(MCS251 *c, int which)
{
    uint8_t b1 = fetch8(c);
    int idx = b1 >> 4;
    int lo = b1 & 0xF;
    if (lo == 4) {
        int j = idx * 2;
        uint16_t a = mcs251_ld_wrj16(c, j);
        uint32_t res, co;
        if (which == 2) { res = (a << 1) & 0xFFFF; co = (a >> 15) & 1; }
        else if (which == 1) { res = a >> 1; co = a & 1; }
        else { res = (uint16_t)((int16_t)a >> 1) & 0xFFFF; co = a & 1; }
        mcs251_st_wrj16(c, j, res & 0xFFFF);
        mcs251_shiftw_flags(c, res, co);
    } else if (lo == 0) {
        uint8_t a = mcs251_ld_reg8(c, idx);
        uint32_t res, co;
        if (which == 2) { res = (a << 1) & 0xFF; co = (a >> 7) & 1; }
        else if (which == 1) { res = a >> 1; co = a & 1; }
        else { res = (uint8_t)((int8_t)a >> 1) & 0xFF; co = a & 1; }
        mcs251_st_reg8(c, idx, res & 0xFF);
        mcs251_shift8_flags(c, res, co);
    } else if (lo == 0xC) {
        int k = idx * 4;
        uint32_t a = mcs251_ld_drk32(c, k);
        uint32_t res, co;
        if (which == 2) { res = (a << 1) & 0xFFFFFFFFu; co = (a >> 31) & 1; }
        else if (which == 1) { res = a >> 1; co = a & 1; }
        else { res = (uint32_t)((int32_t)a >> 1); co = a & 1; }
        mcs251_st_drk32(c, k, res);
        mcs251_shiftw_flags(c, res, co);
    }
}

/* SRA/SRL/SLL Rm,Rm / WRj,WRj / DRk,DRk (0x0C-0x0F / 0x1C-0x1F /
 * 0x3C-0x3F): 第二个寄存器字段被忽略, 语义为移位 1 位。 */
static void regop2_shift(MCS251 *c, uint8_t op0, int which)
{
    uint8_t b1 = fetch8(c);
    int lo = op0 & 0x0F;
    if (lo == 0xC) {
        uint8_t a = mcs251_ld_reg8(c, b1 >> 4);
        uint32_t r, co;
        if (which == 2) { r = (a << 1) & 0xFF; co = (a >> 7) & 1; }
        else if (which == 1) { r = a >> 1; co = a & 1; }
        else { r = (uint8_t)((int8_t)a >> 1) & 0xFF; co = a & 1; }
        mcs251_st_reg8(c, b1 >> 4, r);
        mcs251_shift8_flags(c, r, co);
    } else if (lo == 0xD) {
        int j = (b1 >> 4) * 2;
        uint16_t a = mcs251_ld_wrj16(c, j);
        uint32_t r, co;
        if (which == 2) { r = (a << 1) & 0xFFFF; co = (a >> 15) & 1; }
        else if (which == 1) { r = a >> 1; co = a & 1; }
        else { r = (uint16_t)((int16_t)a >> 1) & 0xFFFF; co = a & 1; }
        mcs251_st_wrj16(c, j, r);
        mcs251_shiftw_flags(c, r, co);
    } else {                    /* 0xF: DRk */
        int k = (b1 >> 4) * 4;
        uint32_t a = mcs251_ld_drk32(c, k);
        uint32_t r, co;
        if (which == 2) { r = (a << 1) & 0xFFFFFFFFu; co = (a >> 31) & 1; }
        else if (which == 1) { r = a >> 1; co = a & 1; }
        else { r = (uint32_t)((int32_t)a >> 1); co = a & 1; }
        mcs251_st_drk32(c, k, r);
        mcs251_shiftw_flags(c, r, co);
    }
}

/* MOV @WRj+dis16,Rm / MOV Rm,@WRj+dis16 家族 (0x09/0x19/0x29/0x39/0x49/
 * 0x59/0x69/0x79, Keil 位移寻址).  4 字节: op enc dis16. */
static void mov_dis(MCS251 *c, uint8_t op0)
{
    uint8_t b1 = fetch8(c);
    uint16_t dis = fetch16be(c);
    int hi = b1 >> 4;
    int lo = b1 & 0xF;
    switch (op0) {
    case 0x09: { /* MOV Rm,@WRj+dis16 */
        uint32_t addr = (mcs251_ld_wrj16(c, lo * 2) + dis) & 0xFFFF;
        mcs251_st_reg8(c, hi, mcs251_ld_mem8(c, addr));
        break; }
    case 0x19: { /* MOV @WRj+dis16,Rm */
        uint32_t addr = (mcs251_ld_wrj16(c, lo * 2) + dis) & 0xFFFF;
        mcs251_st_mem8(c, addr, mcs251_ld_reg8(c, hi));
        break; }
    case 0x49: { /* MOV WRj,@WRj+dis16 (字级位移读, int 数组折叠) */
        uint32_t addr = (mcs251_ld_wrj16(c, lo * 2) + dis) & 0xFFFF;
        mcs251_st_wrj16(c, hi * 2, mcs251_ld_mem16(c, addr));
        break; }
    case 0x59: { /* MOV @WRj+dis16,WRj (字级位移写, int 数组折叠) */
        uint32_t addr = (mcs251_ld_wrj16(c, lo * 2) + dis) & 0xFFFF;
        mcs251_st_mem16(c, addr, mcs251_ld_wrj16(c, hi * 2));
        break; }
    case 0x69: { /* MOV WRj,@DRk+dis16 (far: 路由 XFR/code) */
        uint32_t addr = (mcs251_ld_drk32(c, lo * 4) + dis) & 0xFFFFFF;
        mcs251_st_wrj16(c, hi * 2, mcs251_ld_far16(c, addr));
        break; }
    case 0x79: { /* MOV @DRk+dis16,WRj (far: 路由 XFR/code) */
        uint32_t addr = (mcs251_ld_drk32(c, lo * 4) + dis) & 0xFFFFFF;
        mcs251_st_far16(c, addr, mcs251_ld_wrj16(c, hi * 2));
        break; }
    default: break;   /* 0x29/0x39/0x49/0x59 未用 */
    }
}

/* ------------------------------------------------------------------ */
/* 251 PUSH / POP (Table A-12)                                          */
/* ------------------------------------------------------------------ */
static void push_251(MCS251 *c)
{
    uint8_t b1 = fetch8(c);
    int kind = b1 & 0x0F;
    int idx = b1 >> 4;
    switch (kind) {
    case 0x2: push8(c, fetch8(c)); break;            /* PUSH #data */
    case 0x6: {                                     /* PUSH #data16 */
        uint16_t v = fetch16be(c);
        push8(c, v & 0xFF);
        push8(c, (v >> 8) & 0xFF);
        break; }
    case 0x8: push8(c, mcs251_ld_reg8(c, idx)); break;
    case 0x9:
        push8(c, mcs251_ld_reg8(c, idx * 2));
        push8(c, mcs251_ld_reg8(c, idx * 2 + 1));
        break;
    case 0xB:
        push8(c, mcs251_ld_reg8(c, idx * 4));
        push8(c, mcs251_ld_reg8(c, idx * 4 + 1));
        push8(c, mcs251_ld_reg8(c, idx * 4 + 2));
        push8(c, mcs251_ld_reg8(c, idx * 4 + 3));
        break;
    default: break;
    }
}

static void pop_251(MCS251 *c)
{
    uint8_t b1 = fetch8(c);
    int kind = b1 & 0x0F;
    int idx = b1 >> 4;
    switch (kind) {
    case 0x8: mcs251_st_reg8(c, idx, pop8(c)); break;
    case 0x9:
        mcs251_st_reg8(c, idx * 2 + 1, pop8(c));
        mcs251_st_reg8(c, idx * 2, pop8(c));
        break;
    case 0xB:
        mcs251_st_reg8(c, idx * 4 + 3, pop8(c));
        mcs251_st_reg8(c, idx * 4 + 2, pop8(c));
        mcs251_st_reg8(c, idx * 4 + 1, pop8(c));
        mcs251_st_reg8(c, idx * 4, pop8(c));
        break;
    default: break;
    }
}

/* ------------------------------------------------------------------ */
/* CMP conditional branches (Table 4-10 semantics)                     */
/* ------------------------------------------------------------------ */
static void cmp_branch(MCS251 *c, int type)
{
    int z  = (c->psw1 >> 1) & 1;
    int n  = (c->psw1 >> 5) & 1;
    int cy = (c->psw  >> 7) & 1;
    int ov = (c->psw  >> 2) & 1;
    int cond;
    int nx = n != ov;
    switch (type) {
    case CMP_JE:    cond = z; break;
    case CMP_JNE:   cond = !z; break;
    case CMP_JG:    cond = !cy && !z; break;
    case CMP_JLE:   cond = cy || z; break;
    case CMP_JSL:   cond = nx; break;
    case CMP_JSLE:  cond = nx || z; break;
    case CMP_JSG:   cond = (n == ov) && !z; break;
    case CMP_JSGE:  cond = (n == ov); break;
    default:        cond = 0; break;
    }
    cond_branch(c, cond);
}

/* ------------------------------------------------------------------ */
/* MOV op1,reg (0x7A)                                                   */
/* ------------------------------------------------------------------ */
static void mov_op1_reg(MCS251 *c)
{
    uint8_t b1 = fetch8(c);
    int idx = b1 >> 4;
    int kind = b1 & 0xF;
    switch (kind) {
    case 0x1: { /* MOV dir8,Rm */
        uint8_t d = fetch8(c);
        mcs251_st_direct8(c, d, mcs251_ld_reg8(c, idx));
        break; }
    case 0x5: { /* MOV dir8,WRj (16-bit, little-endian in data space) */
        uint8_t d = fetch8(c);
        mcs251_st_direct8(c, d, mcs251_ld_reg8(c, idx * 2 + 1));
        mcs251_st_direct8(c, d + 1, mcs251_ld_reg8(c, idx * 2));
        break; }
    case 0xD: { /* MOV dir8,DRk (4 bytes at dir8) */
        uint8_t d = fetch8(c);
        for (int i = 0; i < 4; i++)
            mcs251_st_direct8(c, d + i, mcs251_ld_reg8(c, idx * 4 + i));
        break; }
    case 0x9: { /* MOV @WRj,Rm : byte2 = m 0000 */
        uint8_t b2 = fetch8(c);
        uint32_t addr = mcs251_ld_wrj16(c, idx * 2) & 0xFFFF;
        mcs251_st_mem8(c, addr, mcs251_ld_reg8(c, b2 >> 4));
        break; }
    case 0xA: { /* MOV @WRj,WRj : byte2 = ws 0000 */
        uint8_t b2 = fetch8(c);
        uint32_t addr = mcs251_ld_wrj16(c, idx * 2) & 0xFFFF;
        mcs251_st_mem16(c, addr, mcs251_ld_wrj16(c, (b2 >> 4) * 2));
        break; }
    case 0xE: { /* MOV @WRj,DRk : byte2 = k 0000 */
        uint8_t b2 = fetch8(c);
        uint32_t addr = mcs251_ld_wrj16(c, idx * 2) & 0xFFFF;
        mcs251_st_mem32(c, addr, mcs251_ld_drk32(c, (b2 >> 4) * 4));
        break; }
    case 0x2: { /* MOV @Ri,Rm : byte2 = m 000i */
        uint8_t b2 = fetch8(c);
        mcs251_st_mem8(c, mcs251_ld_reg8(c, b2 & 1),
                       mcs251_ld_reg8(c, b2 >> 4));
        break; }
    case 0x6: { /* MOV @Ri,WRj : byte2 = j 000i (16-bit) */
        uint8_t b2 = fetch8(c);
        mcs251_st_mem16(c, mcs251_ld_reg8(c, b2 & 1),
                        mcs251_ld_wrj16(c, (b2 >> 4) * 2));
        break; }
    case 0xB: { /* MOV @DRk,Rm : byte2 = m 0000 (far: 路由 XFR/code) */
        uint8_t b2 = fetch8(c);
        uint32_t addr = mcs251_ld_drk32(c, idx * 4) & 0xFFFFFF;
        mcs251_st_far8(c, addr, mcs251_ld_reg8(c, b2 >> 4));
        break; }
    case 0x3: { /* MOV dir16,Rm */
        uint16_t d = fetch16be(c);
        mcs251_st_mem8(c, d, mcs251_ld_reg8(c, idx));
        break; }
    case 0x7: { /* MOV dir16,WRj (word at dir16) */
        uint16_t d = fetch16be(c);
        mcs251_st_mem16(c, d, mcs251_ld_wrj16(c, idx * 2));
        break; }
    case 0xF: { /* MOV dir16,DRk (dword at dir16) */
        uint16_t d = fetch16be(c);
        mcs251_st_mem32(c, d, mcs251_ld_drk32(c, idx * 4));
        break; }
    default: break;
    }
}

/* EJMP/ECALL addr24, LJMP@WRj, ECALL@DRk, ERET                        */
/* ------------------------------------------------------------------ */
static void ejmp_addr24(MCS251 *c, int call)
{
    uint8_t a2 = fetch8(c);
    uint16_t dest = fetch16be(c);
    (void)a2;   /* Page mode off: high byte ignored */
    if (call)
        push_pc(c);
    c->pc = dest;
}

static void ljmp_wrj(MCS251 *c, int call, int j)
{
    uint16_t addr = mcs251_ld_wrj16(c, j);
    if (call)
        push_pc(c);
    c->pc = addr;
}

static void ejmp_drk_after(MCS251 *c, int k, int call)
{
    uint32_t addr = mcs251_ld_drk32(c, k) & 0xFFFF;
    if (call)
        push_pc(c);
    c->pc = (uint16_t)addr;
}

static void do_eret(MCS251 *c)
{
    pop_pc(c);
}

/* ------------------------------------------------------------------ */
/* decode_8051 (low nibble 0x0-0x5)                                    */
/* ------------------------------------------------------------------ */
static void decode_8051(MCS251 *c, uint8_t op0)
{
    uint8_t dir8, data, ba, byte;
    int bitnum;
    switch (op0) {
    /* --- Keil C251 source 模式 (xsmall): 保留的 8051 兼容指令 --- */
    case 0x00: break;                                    /* NOP */
    case 0x01: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0x02: l_call_jump(c, 0); break;                 /* LJMP */
    case 0x03: do_rr(c); break;                          /* RR A */
    case 0x04: inc_dec_acc(c, 0); break;                 /* INC A */
    case 0x05: inc_dec_direct(c, fetch8(c), 0); break;   /* INC dir8 */
    case 0x06: case 0x07: inc_dec_ri(c, op0 & 1, 0); break;   /* INC @Ri */
    case 0x10: jb_branch(c, fetch8(c), 0, 1); break;     /* JBC bit,rel */
    case 0x11: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0x12: l_call_jump(c, 1); break;                 /* LCALL */
    case 0x13: do_rrc(c); break;                         /* RRC A */
    case 0x14: inc_dec_acc(c, 1); break;                 /* DEC A */
    case 0x15: inc_dec_direct(c, fetch8(c), 1); break;   /* DEC dir8 */
    case 0x16: case 0x17: inc_dec_ri(c, op0 & 1, 1); break;   /* DEC @Ri */
    case 0x20: jb_branch(c, fetch8(c), 0, 0); break;     /* JB bit,rel */
    case 0x21: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0x22: do_ret(c); break;                         /* RET */
    case 0x23: do_rl(c); break;                          /* RL A */
    case 0x24: alu_acc(c, fetch8(c), 0); break;          /* ADD A,#d */
    case 0x25: alu_acc(c, mcs251_ld_direct8(c, fetch8(c)), 0); break;
    case 0x26: case 0x27: alu_acc(c, mcs251_ld_ri8(c, op0 & 1), 0); break; /* ADD A,@Ri */
    case 0x2A: case 0x2B:                               /* ADD A,Rn (保留) */
        alu_acc(c, mcs251_ld_reg8(c, op0 & 7), 0); break;
    case 0x30: jb_branch(c, fetch8(c), 1, 0); break;     /* JNB bit,rel */
    case 0x31: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0x32: do_ret(c);
        /* ★ RETI: 恢复中断屏蔽 (8051 中断响应清 EA, RETI 恢复)。
           随后若有挂起使能中断 (ISR 未清 RI/TI 等标志) 重新请求 —
           并发中断 (UART TX TI+RX RI 重叠) 不丢失。普通 RET (main
           返回) 无 pending, 不影响 restart 判定。 */
        c->in_isr = 0;
        if (mcs251_irq_pending(c))
            c->irq_requested = 1;
        break;                         /* RETI */
    case 0x33: do_rlc(c); break;                         /* RLC A */
    case 0x34: alu_acc(c, fetch8(c), 1); break;          /* ADDC A,#d */
    case 0x35: alu_acc(c, mcs251_ld_direct8(c, fetch8(c)), 1); break;
    case 0x36: case 0x37: alu_acc(c, mcs251_ld_ri8(c, op0 & 1), 1); break;
    case 0x3A: case 0x3B:                               /* ADDC A,Rn (保留) */
        alu_acc(c, mcs251_ld_reg8(c, op0 & 7), 1); break;
    case 0x40: jc_branch(c, 0); break;                   /* JC rel */
    case 0x41: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0x42: {                                        /* ORL dir8,A */
        dir8 = fetch8(c);
        uint8_t a = mcs251_ld_reg8(c, RF_ACC);
        uint8_t d = mcs251_ld_direct8(c, dir8);
        mcs251_logic8_flags(c, d | a);
        mcs251_st_direct8(c, dir8, d | a);
        break; }
    case 0x43: {                                        /* ORL dir8,#d */
        dir8 = fetch8(c);
        data = fetch8(c);
        uint8_t d = mcs251_ld_direct8(c, dir8);
        mcs251_logic8_flags(c, d | data);
        mcs251_st_direct8(c, dir8, d | data);
        break; }
    case 0x44: logic_acc(c, fetch8(c), 1); break;       /* ORL A,#d */
    case 0x45: logic_acc(c, mcs251_ld_direct8(c, fetch8(c)), 1); break;
    case 0x46: case 0x47: logic_acc(c, mcs251_ld_ri8(c, op0 & 1), 1); break;
    case 0x4A: case 0x4B:                               /* ORL A,Rn (保留) */
        logic_acc(c, mcs251_ld_reg8(c, op0 & 7), 1); break;
    case 0x50: jc_branch(c, 1); break;                   /* JNC rel */
    case 0x51: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0x52: {                                        /* ANL dir8,A */
        dir8 = fetch8(c);
        uint8_t a = mcs251_ld_reg8(c, RF_ACC);
        uint8_t d = mcs251_ld_direct8(c, dir8);
        mcs251_logic8_flags(c, d & a);
        mcs251_st_direct8(c, dir8, d & a);
        break; }
    case 0x53: {                                        /* ANL dir8,#d */
        dir8 = fetch8(c);
        data = fetch8(c);
        uint8_t d = mcs251_ld_direct8(c, dir8);
        mcs251_logic8_flags(c, d & data);
        mcs251_st_direct8(c, dir8, d & data);
        break; }
    case 0x54: logic_acc(c, fetch8(c), 0); break;       /* ANL A,#d */
    case 0x55: logic_acc(c, mcs251_ld_direct8(c, fetch8(c)), 0); break;
    case 0x56: case 0x57: logic_acc(c, mcs251_ld_ri8(c, op0 & 1), 0); break;
    case 0x5A: case 0x5B:                               /* ANL A,Rn (保留) */
        logic_acc(c, mcs251_ld_reg8(c, op0 & 7), 0); break;
    case 0x60: jz_branch(c, 0); break;                   /* JZ rel */
    case 0x61: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0x62: {                                        /* XRL dir8,A */
        dir8 = fetch8(c);
        uint8_t a = mcs251_ld_reg8(c, RF_ACC);
        uint8_t d = mcs251_ld_direct8(c, dir8);
        mcs251_logic8_flags(c, d ^ a);
        mcs251_st_direct8(c, dir8, d ^ a);
        break; }
    case 0x63: {                                        /* XRL dir8,#d */
        dir8 = fetch8(c);
        data = fetch8(c);
        uint8_t d = mcs251_ld_direct8(c, dir8);
        mcs251_logic8_flags(c, d ^ data);
        mcs251_st_direct8(c, dir8, d ^ data);
        break; }
    case 0x64: logic_acc(c, fetch8(c), 2); break;       /* XRL A,#d */
    case 0x65: logic_acc(c, mcs251_ld_direct8(c, fetch8(c)), 2); break;
    case 0x66: case 0x67: logic_acc(c, mcs251_ld_ri8(c, op0 & 1), 2); break;
    case 0x70: jz_branch(c, 1); break;                   /* JNZ rel (保留!) */
    case 0x71: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0x72: {                                        /* ORL C,bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_carry(c, ld_carry(c) | ld_bit(c, byte, bitnum));
        break; }
    case 0x73: jmp_a_dptr(c); break;                     /* JMP @A+DPTR */
    case 0x74: mcs251_st_reg8(c, RF_ACC, fetch8(c)); break;  /* MOV A,#d */
    case 0x75: {                                        /* MOV dir8,#d */
        dir8 = fetch8(c);
        data = fetch8(c);
        mcs251_st_direct8(c, dir8, data);
        break; }
    case 0x76: case 0x77:                               /* MOV @Ri,#d */
        mcs251_st_ri8(c, op0 & 1, fetch8(c)); break;
    case 0x7B: mcs251_st_reg8(c, 3, fetch8(c)); break;  /* MOV R3,#d (保留) */
    case 0x80: do_sjmp(c); break;                        /* SJMP */
    case 0x81: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0x82: {                                        /* ANL C,bit (保留!) */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_carry(c, ld_carry(c) & ld_bit(c, byte, bitnum));
        break; }
    case 0x83: do_movc(c, c->pc); break;                 /* MOVC A,@A+PC */
    case 0x84: do_div_ab(c); break;                      /* DIV AB */
    case 0x85: {                                        /* MOV dir8,dir8 */
        uint8_t d1 = fetch8(c);
        uint8_t d2 = fetch8(c);
        mcs251_st_direct8(c, d2, mcs251_ld_direct8(c, d1));
        break; }
    case 0x86: case 0x87:                               /* MOV dir8,@Ri */
        mcs251_st_direct8(c, fetch8(c), mcs251_ld_ri8(c, op0 & 1)); break;
    case 0x88: case 0x8B: case 0x8E: case 0x8F:         /* MOV dir8,Rn (保留) */
        mcs251_st_direct8(c, fetch8(c), mcs251_ld_reg8(c, op0 & 7)); break;
    case 0x90: mcs251_st_dptr(c, fetch16be(c)); break;   /* MOV DPTR,#d16 */
    case 0x91: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0x92: {                                        /* MOV bit,C */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_bit(c, byte, bitnum, ld_carry(c));
        break; }
    case 0x93: do_movc(c, mcs251_ld_dptr(c)); break;     /* MOVC A,@A+DPTR */
    case 0x94: alu_acc(c, fetch8(c), 2); break;          /* SUBB A,#d */
    case 0x95: alu_acc(c, mcs251_ld_direct8(c, fetch8(c)), 2); break;
    case 0x96: case 0x97: alu_acc(c, mcs251_ld_ri8(c, op0 & 1), 2); break;
    case 0x98: alu_acc(c, mcs251_ld_reg8(c, 0), 2); break;   /* SUBB A,R0 */
    case 0xA0: {                                        /* ORL C,/bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_carry(c, ld_carry(c) | !ld_bit(c, byte, bitnum));
        break; }
    case 0xA1: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0xA2: {                                        /* MOV C,bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_carry(c, ld_bit(c, byte, bitnum));
        break; }
    case 0xA3: inc_dptr(c); break;                       /* INC DPTR */
    case 0xA4: do_mul_ab(c); break;                      /* MUL AB */
    case 0xA6: case 0xA7:                               /* MOV @Ri,dir8 */
        mcs251_st_ri8(c, op0 & 1, mcs251_ld_direct8(c, fetch8(c))); break;
    case 0xA8: case 0xAB:                               /* MOV Rn,dir8 (保留) */
        mcs251_st_reg8(c, op0 & 7, mcs251_ld_direct8(c, fetch8(c))); break;
    case 0xB0: {                                        /* ANL C,/bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_carry(c, ld_carry(c) & !ld_bit(c, byte, bitnum));
        break; }
    case 0xB1: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0xB2: {                                        /* CPL bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        mcs251_st_direct8(c, byte,
                          mcs251_ld_direct8(c, byte) ^ (1 << bitnum));
        break; }
    case 0xB3: st_carry(c, !ld_carry(c)); break;         /* CPL C */
    case 0xB4: cjne_a(c, fetch8(c)); break;              /* CJNE A,#d,rel */
    case 0xB5: cjne_a(c, mcs251_ld_direct8(c, fetch8(c))); break;
    case 0xB6: case 0xB7: cjne_ri(c, op0 & 1); break;    /* CJNE @Ri,#d,rel */
    case 0xB8: case 0xBA: case 0xBB:                    /* CJNE Rn,#d,rel */
        cjne_rn(c, op0 & 7); break;
    case 0xC0: push8(c, mcs251_ld_direct8(c, fetch8(c))); break; /* PUSH */
    case 0xC1: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0xC2: {                                        /* CLR bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_bit(c, byte, bitnum, 0);
        break; }
    case 0xC3: st_carry(c, 0); break;                    /* CLR C */
    case 0xC4: do_swap(c); break;                        /* SWAP A */
    case 0xC5: {                                        /* XCH A,dir8 */
        dir8 = fetch8(c);
        uint8_t t = mcs251_ld_direct8(c, dir8);
        uint8_t a = mcs251_ld_reg8(c, RF_ACC);
        mcs251_st_direct8(c, dir8, a);
        mcs251_st_reg8(c, RF_ACC, t);
        break; }
    case 0xC6: case 0xC7: {                             /* XCH A,@Ri */
        int i = op0 & 1;
        uint8_t t = mcs251_ld_ri8(c, i);
        uint8_t a = mcs251_ld_reg8(c, RF_ACC);
        mcs251_st_ri8(c, i, a);
        mcs251_st_reg8(c, RF_ACC, t);
        break; }
    case 0xC8: case 0xC9: case 0xCB: case 0xCC:
    case 0xCD: case 0xCE: case 0xCF: {                  /* XCH A,Rn */
        int n = op0 & 7;
        uint8_t t = mcs251_ld_reg8(c, n);
        uint8_t a = mcs251_ld_reg8(c, RF_ACC);
        mcs251_st_reg8(c, n, a);
        mcs251_st_reg8(c, RF_ACC, t);
        break; }
    case 0xD0: mcs251_st_direct8(c, fetch8(c), pop8(c)); break; /* POP */
    case 0xD1: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0xD2: {                                        /* SETB bit */
        ba = fetch8(c);
        bit_8051_decode(ba, &byte, &bitnum);
        st_bit(c, byte, bitnum, 1);
        break; }
    case 0xD3: st_carry(c, 1); break;                    /* SETB C */
    case 0xD4: do_da(c); break;                          /* DA A */
    case 0xD5: djnz_direct(c, fetch8(c)); break;         /* DJNZ dir8,rel */
    case 0xD6: case 0xD7: xchd(c, op0 & 1); break;       /* XCHD A,@Ri */
    case 0xD8: case 0xD9: case 0xDB:                    /* DJNZ Rn,rel */
        djnz_reg(c, op0 & 7); break;
    case 0xE0: movx_a_dptr(c); break;                    /* MOVX A,@DPTR */
    case 0xE1: a_call_jump(c, op0, 0); break;            /* AJMP */
    case 0xE2: case 0xE3: movx_a_ri(c, op0 & 1); break;  /* MOVX A,@Ri */
    case 0xE4: clr_cpl_acc(c, 0); break;                 /* CLR A */
    case 0xE5: mcs251_st_reg8(c, RF_ACC,
                              mcs251_ld_direct8(c, fetch8(c))); break;
    case 0xE6: case 0xE7: mcs251_st_reg8(c, RF_ACC,
                              mcs251_ld_ri8(c, op0 & 1)); break;  /* MOV A,@Ri */
    case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF: {       /* MOV A,Rn */
        uint8_t t = mcs251_ld_reg8(c, op0 & 7);
        mcs251_st_reg8(c, RF_ACC, t);
        mcs251_set_parity(c, t);
        break; }
    case 0xF0: movx_dptr_a(c); break;                    /* MOVX @DPTR,A */
    case 0xF1: a_call_jump(c, op0, 1); break;            /* ACALL */
    case 0xF2: case 0xF3: movx_ri_a(c, op0 & 1); break;  /* MOVX @Ri,A */
    case 0xF4: clr_cpl_acc(c, 1); break;                 /* CPL A */
    case 0xF5: { uint8_t _d = fetch8(c);
                 mcs251_st_direct8(c, _d, mcs251_ld_reg8(c, RF_ACC)); break; }
    case 0xF6: case 0xF7:                               /* MOV @Ri,A */
        mcs251_st_ri8(c, op0 & 1, mcs251_ld_reg8(c, RF_ACC)); break;
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:         /* MOV Rn,A */
        mcs251_st_reg8(c, op0 & 7, mcs251_ld_reg8(c, RF_ACC)); break;
    default: break;
    }
}

/* ------------------------------------------------------------------ */
/* decode_a5: MCS-51 @Ri/Rn forms in Source mode                       */
/*   A5 x6/A5 x7 = @Ri form, A5 x8-A5 xF = Rn form                    */
/* ------------------------------------------------------------------ */
static void decode_a5(MCS251 *c)
{
    uint8_t op1 = fetch8(c);
    int hi = op1 >> 4;
    int lo = op1 & 0x0F;

    if (lo >= 8) {
        int n = lo & 7;   /* Rn (0-7) */
        switch (hi) {
        case 0x0: inc_dec_reg(c, n, 0); break;   /* INC Rn */
        case 0x1: inc_dec_reg(c, n, 1); break;   /* DEC Rn */
        case 0x2: alu_acc(c, mcs251_ld_reg8(c, n), 0); break;  /* ADD */
        case 0x3: alu_acc(c, mcs251_ld_reg8(c, n), 1); break;  /* ADDC */
        case 0x4: logic_acc(c, mcs251_ld_reg8(c, n), 1); break; /* ORL */
        case 0x5: logic_acc(c, mcs251_ld_reg8(c, n), 0); break; /* ANL */
        case 0x6: logic_acc(c, mcs251_ld_reg8(c, n), 2); break; /* XRL */
        case 0x7: mcs251_st_reg8(c, n, fetch8(c)); break; /* MOV Rn,#d */
        case 0x8: mcs251_st_direct8(c, fetch8(c),
                                    mcs251_ld_reg8(c, n)); break; /* MOV dir8,Rn */
        case 0x9: alu_acc(c, mcs251_ld_reg8(c, n), 2); break;  /* SUBB */
        case 0xA: mcs251_st_reg8(c, n,
                                 mcs251_ld_direct8(c, fetch8(c))); break; /* MOV Rn,dir8 */
        case 0xB: cjne_rn(c, n); break;             /* CJNE Rn,#d,rel */
        case 0xC: {                                 /* XCH A,Rn */
            uint8_t t = mcs251_ld_reg8(c, n);
            uint8_t a = mcs251_ld_reg8(c, RF_ACC);
            mcs251_st_reg8(c, n, a);
            mcs251_st_reg8(c, RF_ACC, t);
            break; }
        case 0xD: djnz_reg(c, n); break;            /* DJNZ Rn,rel */
        case 0xE: {                                 /* MOV A,Rn */
            uint8_t t = mcs251_ld_reg8(c, n);
            mcs251_st_reg8(c, RF_ACC, t);
            mcs251_set_parity(c, t);
            break; }
        case 0xF: mcs251_st_reg8(c, n, mcs251_ld_reg8(c, RF_ACC)); break;
        default: break;
        }
    } else {
        int i = lo & 1;   /* @R0/@R1 — indirect via R0/R1 value */
        switch (hi) {
        case 0x0: inc_dec_ri(c, i, 0); break;   /* INC @Ri */
        case 0x1: inc_dec_ri(c, i, 1); break;   /* DEC @Ri */
        case 0x2: alu_acc(c, mcs251_ld_ri8(c, i), 0); break;  /* ADD */
        case 0x3: alu_acc(c, mcs251_ld_ri8(c, i), 1); break;  /* ADDC */
        case 0x4: logic_acc(c, mcs251_ld_ri8(c, i), 1); break; /* ORL */
        case 0x5: logic_acc(c, mcs251_ld_ri8(c, i), 0); break; /* ANL */
        case 0x6: logic_acc(c, mcs251_ld_ri8(c, i), 2); break; /* XRL */
        case 0x7: mcs251_st_ri8(c, i, fetch8(c)); break; /* MOV @Ri,#d */
        case 0x8: mcs251_st_direct8(c, fetch8(c),
                                    mcs251_ld_ri8(c, i)); break; /* MOV dir8,@Ri */
        case 0x9: alu_acc(c, mcs251_ld_ri8(c, i), 2); break;  /* SUBB */
        case 0xA: mcs251_st_ri8(c, i,
                                 mcs251_ld_direct8(c, fetch8(c))); break; /* MOV @Ri,dir8 */
        case 0xB: cjne_ri(c, i); break;             /* CJNE @Ri,#d,rel */
        case 0xC: {                                 /* XCH A,@Ri */
            uint8_t t = mcs251_ld_ri8(c, i);
            uint8_t a = mcs251_ld_reg8(c, RF_ACC);
            mcs251_st_ri8(c, i, a);
            mcs251_st_reg8(c, RF_ACC, t);
            break; }
        case 0xD: xchd(c, i); break;                /* XCHD A,@Ri */
        case 0xE: {                                 /* MOV A,@Ri */
            uint8_t t = mcs251_ld_ri8(c, i);
            mcs251_st_reg8(c, RF_ACC, t);
            mcs251_set_parity(c, t);
            break; }
        case 0xF: mcs251_st_ri8(c, i, mcs251_ld_reg8(c, RF_ACC)); break;
        default: break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* decode_bit: A9 bit instructions (Table A-10/A-11)                   */
/*   A9 xxxx 0 bit dir8                                                */
/* ------------------------------------------------------------------ */
/* A9 扩展位指令: 第二字节低 3 位 = 位号, 第三字节 = 直接字节地址
 * (SFR 字节地址 0x80-0xFF 或 IRAM 0x20-0x2F)。与 8051 两字节位指令
 * (A2/92/D2/C2/B2: 第三字节 = 位地址, 字节=dir&0xF8, 位=dir&7) 不同!
 * 验证: Keil `EAXFR=1` → A9 D7 BA (byte=0xBA=P_SW2, bit=7);
 *       `T1x12=1` → A9 D6 8E (byte=0x8E=AUXR, bit=6)。 */
static uint8_t ld_bit_a9(MCS251 *c, uint8_t byte, int bitnum)
{
    return (mcs251_ld_direct8(c, byte) >> bitnum) & 1;
}

static void st_bit_a9(MCS251 *c, uint8_t byte, int bitnum, uint8_t val)
{
    uint8_t old = mcs251_ld_direct8(c, byte);
    old &= (uint8_t)~(1 << bitnum);
    old |= (uint8_t)((val & 1) << bitnum);
    mcs251_st_direct8(c, byte, old);
}

static void decode_bit(MCS251 *c)
{
    uint8_t b1 = fetch8(c);
    uint8_t dir8 = fetch8(c);
    int hi = b1 >> 4;
    int bitnum = b1 & 7;

    switch (hi) {
    case 0x1: /* JBC bit,rel */
        if (ld_bit_a9(c, dir8, bitnum)) {
            st_bit_a9(c, dir8, bitnum, 0);
            cond_branch(c, 1);
        } else {
            cond_branch(c, 0);
        }
        break;
    case 0x2: cond_branch(c, ld_bit_a9(c, dir8, bitnum)); break;  /* JB */
    case 0x3: cond_branch(c, !ld_bit_a9(c, dir8, bitnum)); break; /* JNB */
    case 0x7: st_carry(c, ld_carry(c) | ld_bit_a9(c, dir8, bitnum)); break; /* ORL CY,bit */
    case 0x8: st_carry(c, ld_carry(c) & ld_bit_a9(c, dir8, bitnum)); break; /* ANL CY,bit */
    case 0x9: st_bit_a9(c, dir8, bitnum, ld_carry(c)); break;   /* MOV bit,CY */
    case 0xA: st_carry(c, ld_bit_a9(c, dir8, bitnum)); break;   /* MOV CY,bit */
    case 0xB: st_bit_a9(c, dir8, bitnum,
                        !ld_bit_a9(c, dir8, bitnum)); break;   /* CPL bit */
    case 0xC: st_bit_a9(c, dir8, bitnum, 0); break;            /* CLR bit */
    case 0xD: st_bit_a9(c, dir8, bitnum, 1); break;            /* SETB bit */
    case 0xE: st_carry(c, ld_carry(c) | !ld_bit_a9(c, dir8, bitnum)); break; /* ORL CY,/bit */
    case 0xF: st_carry(c, ld_carry(c) & !ld_bit_a9(c, dir8, bitnum)); break; /* ANL CY,/bit */
    default: break;
    }
}

/* True for MCS-251 source-mode 251-specific opcodes; everything else
 * is decoded as the 8051-compatible set (Keil C251 output). */
static int is_251_op(uint8_t op0)
{
    /* Keil C251 source 模式 251 原生 opcode (替换同地址 8051 指令),
     * 按 tcc_c251 发射函数 (c251-hex.c) 与真实 Keil source+xsmall hex 验证。 */
    switch (op0) {
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x0C: case 0x0D: case 0x0E: case 0x0F:
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x1C: case 0x1D: case 0x1E: case 0x1F:
    case 0x28: case 0x29:
    case 0x2C: case 0x2D: case 0x2E: case 0x2F:
    case 0x38: case 0x39:
    case 0x3C: case 0x3D: case 0x3E: case 0x3F:
    case 0x48: case 0x49:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
    case 0x58: case 0x59:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x68: case 0x69:
    case 0x6A: case 0x6B:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0x78: case 0x79: case 0x7A:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
    case 0x89: case 0x8A: case 0x8C: case 0x8D:
    case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xAA: case 0xB9:
    case 0xAC: case 0xAD: case 0xAE: case 0xAF:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
    case 0xCA: case 0xDA:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        return 1;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* decode_251 (Table A-7)                                              */
/* ------------------------------------------------------------------ */
static void decode_251(MCS251 *c, uint8_t op0)
{
    uint8_t b1;
    switch (op0) {
    /* --- Keil C251 source 模式 251 原生指令 (替换了同地址 8051 opcode) --- */
    case 0x08: cmp_branch(c, CMP_JSLE); break;   /* JSLE (有符号<=) */
    case 0x18: cmp_branch(c, CMP_JSG); break;    /* JSG  (有符号>) */
    case 0x28: cmp_branch(c, CMP_JLE); break;    /* JLE  (无符号<=) */
    case 0x38: cmp_branch(c, CMP_JG); break;     /* JG   (无符号>) */
    case 0x48: cmp_branch(c, CMP_JSL); break;    /* JSL  (有符号<) */
    case 0x58: cmp_branch(c, CMP_JSGE); break;   /* JSGE (有符号>=) */
    case 0x68: cmp_branch(c, CMP_JE); break;     /* JE rel8 */
    case 0x78: cmp_branch(c, CMP_JNE); break;    /* JNE rel8 */
    case 0x09: case 0x19: case 0x29: case 0x39:
    case 0x49: case 0x59: case 0x69: case 0x79:
        mov_dis(c, op0); break;                  /* 位移 MOV 家族 */
    case 0x0A: do_movz(c, 0); break;             /* MOVZ WRj,Rm */
    case 0x1A: do_movz(c, 1); break;             /* MOVS WRj,Rm */
    case 0x0B: inc_dec_short(c, 0); break;       /* INC short / MOV WRn,@ */
    case 0x1B: inc_dec_short(c, 1); break;       /* DEC short / MOV @,WRn */
    case 0x0E: shift_single(c, 0); break;        /* SRA Rm/WRj/DRk */
    case 0x1E: shift_single(c, 1); break;        /* SRL ... */
    case 0x3E: shift_single(c, 2); break;        /* SLL ... */
    case 0x0C: case 0x0D: case 0x0F:             /* SRA Rm,Rm / WRj,WRj / DRk,DRk */
        regop2_shift(c, op0, 0); break;
    case 0x1C: case 0x1D: case 0x1F:             /* SRL ... */
        regop2_shift(c, op0, 1); break;
    case 0x3C: case 0x3D: case 0x3F:             /* SLL ... */
        regop2_shift(c, op0, 2); break;
    case 0x6A: {                                 /* CMP Rm,#data8 (3B) */
        b1 = fetch8(c);
        uint8_t data = fetch8(c);
        sub8(c, -1, mcs251_ld_reg8(c, b1 >> 4), data, 0);
        break; }
    case 0x6B: case 0x9B: {                      /* CMP Rm,Rm (2B) */
        b1 = fetch8(c);
        regop2_byte(c, OP_CMP, b1 >> 4, b1 & 0xF);
        break; }
    case 0x7A: mov_op1_reg(c); break;            /* MOV op1,reg (变长) */
    case 0x89: {  /* LJMP @WRj / EJMP @DRk */
        b1 = fetch8(c);
        if ((b1 & 0xF) == 0x8)      ejmp_drk_after(c, (b1 >> 4) * 4, 0);
        else                        ljmp_wrj(c, 0, (b1 >> 4) * 2);
        break; }
    case 0x8A: ejmp_addr24(c, 0); break;         /* EJMP addr24 */
    case 0x8C: { /* DIV Rm,Rm */
        b1 = fetch8(c);
        regop2_byte(c, OP_DIV, b1 >> 4, b1 & 0xF);
        break; }
    case 0x8D: { /* DIV WRj,WRj */
        b1 = fetch8(c);
        regop2_word(c, OP_DIV, (b1 >> 4) * 2, (b1 & 0xF) * 2);
        break; }
    case 0x99: {  /* LCALL @WRj / ECALL @DRk */
        b1 = fetch8(c);
        if ((b1 & 0xF) == 0x8)      ejmp_drk_after(c, (b1 >> 4) * 4, 1);
        else                        ljmp_wrj(c, 1, (b1 >> 4) * 2);
        break; }
    case 0x9A: ejmp_addr24(c, 1); break;         /* ECALL addr24 */
    case 0xAA: do_eret(c); break;                /* ERET */
    case 0xB9: break;                            /* TRAP (no-op) */
    case 0xCA: push_251(c); break;               /* PUSH op1 */
    case 0xDA: pop_251(c); break;                /* POP op1 */
    default:
        /* regop2 家族 (C=byte D=word E=变长 F=dword): ADD/ORL/ANL/XRL/
         * MOV/SUB/MUL/CMP/XRL. */
        if ((op0 & 0x0F) >= 0xC && op_from_hi(op0 >> 4) >= 0)
            decode_regop2(c, op0);
        break;
    }
}


