/*
 * decode.c — MCS-251 instruction decoder & executor (Source Mode).
 *
 * Direct translation of QEMU target/mcs251/translate.c + translate_impl.c.inc
 * into a simple fetch/decode/execute interpreter.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "mcs251.h"

/* ------------------------------------------------------------------ */
/* Fetch helpers (advance pc)                                          */
/* ------------------------------------------------------------------ */

static uint8_t fetch8(MCS251 *c)
{
    uint8_t b = c->code[c->pc & (MCS251_CODE_SIZE - 1)];
    c->pc = (uint16_t)(c->pc + 1);
    return b;
}

/* fetch_op8: 取操作码 + 逃逸检测合并 (speed)。原 execute_one 在取指后
 * 用 iaddr=pc-1 做范围检查; 这里把同一逻辑前移到取指阶段, 每次只对
 * 指令首地址做一次检查 (操作数仍走 fetch8, 不重复检查)。行为等价:
 * 逃逸 = PC 落在装载范围外, escape_pc=逃逸指令地址, escape_src=前一条
 * 范围内指令 (首次就逃逸时为 0)。 */
static uint8_t fetch_op8(MCS251 *c)
{
    uint8_t op = c->code[c->pc & (MCS251_CODE_SIZE - 1)];
    uint16_t iaddr = (uint16_t)c->pc;
    c->pc = (uint16_t)(c->pc + 1);
    if (!c->escaped) {
        if (c->code_hi && (iaddr < c->code_lo || iaddr > c->code_hi)) {
            c->escaped = 1;
            c->escape_pc = iaddr;
            c->escape_src = c->last_pc;
        } else {
            c->last_pc = iaddr;
        }
    }
    return op;
}

static uint16_t fetch16be(MCS251 *c)
{
    uint8_t hi = fetch8(c);
    uint8_t lo = fetch8(c);
    return (uint16_t)((hi << 8) | lo);
}

static uint16_t rel_target(MCS251 *c, int8_t rel)
{
    return (uint16_t)((c->pc + rel) & 0xFFFF);
}

/* ------------------------------------------------------------------ */
/* Bit addressing (8051 bit addr -> byte/bitnum)                       */
/* ------------------------------------------------------------------ */

static void bit_8051_decode(uint8_t ba, uint8_t *byte, int *bitnum)
{
    if (ba < 0x80) {
        *byte   = 0x20 + (ba >> 3);
        *bitnum = ba & 7;
    } else {
        *byte   = ba & 0xF8;
        *bitnum = ba & 7;
    }
}

static uint8_t ld_bit(MCS251 *c, uint8_t byte, int bitnum)
{
    return (mcs251_ld_direct8(c, byte) >> bitnum) & 1;
}

static void st_bit(MCS251 *c, uint8_t byte, int bitnum, uint8_t val)
{
    uint8_t old = mcs251_ld_direct8(c, byte);
    old &= ~(1 << bitnum);
    old |= (val & 1) << bitnum;
    mcs251_st_direct8(c, byte, old);
}

static uint8_t ld_carry(MCS251 *c)
{
    return (c->psw >> 7) & 1;
}

static void st_carry(MCS251 *c, uint8_t v)
{
    c->psw = (c->psw & ~PSW_CY) | ((v & 1) << 7);
}

/* ------------------------------------------------------------------ */
/* Stack                                                              */
/* ------------------------------------------------------------------ */

static uint16_t get_sp(MCS251 *c)
{
    return (uint16_t)(c->rf[RF_SPX] | (c->rf[RF_SPX + 1] << 8));
}

static void set_sp(MCS251 *c, uint16_t sp)
{
    c->rf[RF_SPX]     = sp & 0xFF;
    c->rf[RF_SPX + 1] = (sp >> 8) & 0xFF;
}

int g_trace_stack = 0;   /* --trace-stack: PUSH/POP/CALL/RET 栈追踪 (调试用) */
int g_trace_stkwr = 0;   /* --trace-stkwr: 栈区 (0xBC-0x1BB) 内存写追踪 */
int g_trace_watch = -1;  /* --trace-watch ADDR: 检测 iram[ADDR] 变化并报告指令 */

static void push8(MCS251 *c, uint8_t val)
{
    uint16_t addr = (uint16_t)(get_sp(c) + 1);
    mcs251_st_iram8(c, addr, val);
    set_sp(c, addr);
    if (g_trace_stack)
        fprintf(stderr, "[STK] PUSH %02X -> 0x%04X (SP=%04X) cy=%llu\n",
                val, addr, addr, (unsigned long long)c->cycles);
}

static uint8_t pop8(MCS251 *c)
{
    uint16_t addr = get_sp(c);
    uint8_t v = mcs251_ld_iram8(c, addr);
    set_sp(c, (uint16_t)(addr - 1));
    if (g_trace_stack)
        fprintf(stderr, "[STK] POP  %02X from 0x%04X (SP=%04X) cy=%llu\n",
                v, addr, addr - 1, (unsigned long long)c->cycles);
    return v;
}

/* CALL: push PC (low then high) and jump. */
static void push_pc(MCS251 *c)
{
    push8(c, c->pc & 0xFF);
    push8(c, (c->pc >> 8) & 0xFF);
    /* RET 一致性: 记录返回地址位图 (任何 push 都是合法 RET 目标) */
    c->ret_pushed[c->pc >> 3] |= (uint8_t)(1 << (c->pc & 7));
    if (g_trace_stack)
        fprintf(stderr, "[STK] CALL -> ret 0x%04X (SP=%04X) cy=%llu\n",
                c->pc, get_sp(c), (unsigned long long)c->cycles);
}

/* RET: pop PC high then low. */
static void pop_pc(MCS251 *c)
{
    uint8_t hi = pop8(c);
    uint8_t lo = pop8(c);
    c->pc = (uint16_t)((hi << 8) | lo);
    if (g_trace_stack)
        fprintf(stderr, "[STK] RET -> 0x%04X (SP=%04X) cy=%llu\n",
                c->pc, get_sp(c), (unsigned long long)c->cycles);
}

/* ------------------------------------------------------------------ */
/* Branch helper: read rel, jump if cond != 0                         */
/* ------------------------------------------------------------------ */

static void cond_branch(MCS251 *c, int cond)
{
    int8_t rel = (int8_t)fetch8(c);
    if (cond)
        c->pc = rel_target(c, rel);
}

/* ------------------------------------------------------------------ */
/* 8-bit ALU with accumulator                                          */
/* ------------------------------------------------------------------ */

/* op: 0=ADD 1=ADDC 2=SUBB */
static void alu_acc(MCS251 *c, uint8_t src, int op)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint32_t res;
    if (op == 0) {
        res = a + src;
        mcs251_add8_flags(c, res, a, src, 0, 1);
    } else if (op == 1) {
        uint8_t cin = ld_carry(c);
        res = a + src + cin;
        mcs251_add8_flags(c, res, a, src, cin, 1);
    } else {
        uint8_t borrow = ld_carry(c);
        res = a - src - borrow;
        mcs251_sub8_flags(c, res, a, src, borrow, 1);
    }
    mcs251_st_reg8(c, RF_ACC, res & 0xFF);
}

/* op: 0=ANL 1=ORL 2=XRL */
static void logic_acc(MCS251 *c, uint8_t src, int op)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint32_t res = (op == 0) ? (a & src) : (op == 1) ? (a | src) : (a ^ src);
    mcs251_logic8_flags(c, res);
    mcs251_st_reg8(c, RF_ACC, res & 0xFF);
    mcs251_set_parity(c, res);
}

/* ------------------------------------------------------------------ */
/* Rotate / shift / misc (8-bit)                                       */
/* ------------------------------------------------------------------ */

static void do_rr(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t res = (uint8_t)((a >> 1) | (a << 7));
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_logic8_flags(c, res);
    mcs251_set_parity(c, res);
}

static void do_rl(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t res = (uint8_t)((a << 1) | (a >> 7));
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_logic8_flags(c, res);
    mcs251_set_parity(c, res);
}

static void do_rrc(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t co = a & 1;
    uint8_t res = (uint8_t)((a >> 1) | (ld_carry(c) << 7));
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_shift8_flags(c, res, co);
    mcs251_set_parity(c, res);
}

static void do_rlc(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t co = (a >> 7) & 1;
    uint8_t res = (uint8_t)((a << 1) | ld_carry(c));
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_shift8_flags(c, res, co);
    mcs251_set_parity(c, res);
}

static void do_swap(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t res = (uint8_t)((a << 4) | (a >> 4));
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_logic8_flags(c, res);
    mcs251_set_parity(c, res);
}

static void clr_cpl_acc(MCS251 *c, int cpl)
{
    uint8_t res = cpl ? (uint8_t)~mcs251_ld_reg8(c, RF_ACC) : 0;
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_logic8_flags(c, res);
    mcs251_set_parity(c, res);
}

static void do_da(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t add = 0;
    if (((a & 0xF) > 9) || ((c->psw >> 6) & 1))
        add |= 0x06;
    if ((a > 0x99) || ld_carry(c))
        add |= 0x60;
    uint8_t res = (uint8_t)(a + add);
    mcs251_st_reg8(c, RF_ACC, res);
    st_carry(c, ((uint32_t)(a + add) >> 8) & 1);
    mcs251_logic8_flags(c, res);
    mcs251_set_parity(c, res);
}

/* ------------------------------------------------------------------ */
/* MUL AB / DIV AB                                                     */
/* ------------------------------------------------------------------ */

static void do_mul_ab(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t b = mcs251_ld_reg8(c, RF_B);
    uint16_t res = (uint16_t)(a * b);
    mcs251_st_reg8(c, RF_ACC, res & 0xFF);
    mcs251_st_reg8(c, RF_B, (res >> 8) & 0xFF);
    mcs251_muldiv8_flags(c, res > 0xFF);
    mcs251_logic8_flags(c, res & 0xFF);
}

static void do_div_ab(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t b = mcs251_ld_reg8(c, RF_B);
    uint8_t q = 0, r = 0, ov = 0;
    if (b != 0) {
        q = a / b;
        r = a % b;
    } else {
        ov = 1;
    }
    mcs251_st_reg8(c, RF_ACC, q);
    mcs251_st_reg8(c, RF_B, r);
    mcs251_muldiv8_flags(c, ov);
}

/* ------------------------------------------------------------------ */
/* INC / DEC                                                          */
/* ------------------------------------------------------------------ */

static void inc_dec_acc(MCS251 *c, int dec)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t res = dec ? (uint8_t)(a - 1) : (uint8_t)(a + 1);
    mcs251_st_reg8(c, RF_ACC, res);
    mcs251_logic8_flags(c, res);
    mcs251_set_parity(c, res);
}

static void inc_dec_reg(MCS251 *c, int n, int dec)
{
    uint8_t a = mcs251_ld_reg8(c, n);
    uint8_t res = dec ? (uint8_t)(a - 1) : (uint8_t)(a + 1);
    mcs251_st_reg8(c, n, res);
    mcs251_logic8_flags(c, res);
}

static void inc_dec_direct(MCS251 *c, uint8_t dir8, int dec)
{
    uint8_t a = mcs251_ld_direct8(c, dir8);
    uint8_t res = dec ? (uint8_t)(a - 1) : (uint8_t)(a + 1);
    mcs251_st_direct8(c, dir8, res);
    mcs251_logic8_flags(c, res);
}

static void inc_dec_ri(MCS251 *c, int i, int dec)
{
    uint8_t a = mcs251_ld_ri8(c, i);
    uint8_t res = dec ? (uint8_t)(a - 1) : (uint8_t)(a + 1);
    mcs251_st_ri8(c, i, res);
    mcs251_logic8_flags(c, res);
}

static void inc_dptr(MCS251 *c)
{
    mcs251_st_dptr(c, (uint16_t)(mcs251_ld_dptr(c) + 1));
}

/* ------------------------------------------------------------------ */
/* Control flow (MCS-51)                                               */
/* ------------------------------------------------------------------ */

static void a_call_jump(MCS251 *c, uint8_t op0, int call)
{
    uint8_t b1 = fetch8(c);
    uint16_t page = c->pc & 0xF800;
    uint16_t addr11 = (uint16_t)(((op0 & 0x07) << 8) | b1);
    uint16_t dest = (uint16_t)((page | addr11) & 0xFFFF);
    if (call)
        push_pc(c);
    c->pc = dest;
}

static void l_call_jump(MCS251 *c, int call)
{
    uint16_t dest = fetch16be(c);
    if (call)
        push_pc(c);
    c->pc = dest;
}

static void do_sjmp(MCS251 *c)
{
    int8_t rel = (int8_t)fetch8(c);
    c->pc = rel_target(c, rel);
}

static void do_ret(MCS251 *c)
{
    pop_pc(c);
}

static void jmp_a_dptr(MCS251 *c)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    c->pc = (uint16_t)((mcs251_ld_dptr(c) + a) & 0xFFFF);
}

static void jc_branch(MCS251 *c, int nc)
{
    cond_branch(c, nc ? !ld_carry(c) : ld_carry(c));
}

static void jz_branch(MCS251 *c, int nz)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    cond_branch(c, nz ? (a != 0) : (a == 0));
}

/* JB/JNB/JBC bit,rel  (ba = 8051 bit address) */
static void jb_branch(MCS251 *c, uint8_t ba, int nb, int clr)
{
    uint8_t byte;
    int bitnum;
    bit_8051_decode(ba, &byte, &bitnum);
    uint8_t bit = ld_bit(c, byte, bitnum);
    if (clr)
        st_bit(c, byte, bitnum, 0);
    cond_branch(c, nb ? !bit : bit);
}

/* CJNE A,src,rel: CY = borrow, branch if A != src */
static void cjne_a(MCS251 *c, uint8_t src)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint32_t res = a - src;
    st_carry(c, (res >> 8) & 1);
    cond_branch(c, a != src);
}

static void cjne_rn(MCS251 *c, int n)
{
    uint8_t data = fetch8(c);
    uint8_t r = mcs251_ld_reg8(c, n);
    uint32_t res = r - data;
    st_carry(c, (res >> 8) & 1);
    cond_branch(c, r != data);
}

static void cjne_ri(MCS251 *c, int i)
{
    uint8_t data = fetch8(c);
    uint8_t r = mcs251_ld_ri8(c, i);
    uint32_t res = r - data;
    st_carry(c, (res >> 8) & 1);
    cond_branch(c, r != data);
}

static void djnz_reg(MCS251 *c, int n)
{
    uint8_t r = mcs251_ld_reg8(c, n);
    uint8_t res = (uint8_t)(r - 1);
    mcs251_st_reg8(c, n, res);
    mcs251_logic8_flags(c, res);
    cond_branch(c, res != 0);
}

static void djnz_direct(MCS251 *c, uint8_t dir8)
{
    uint8_t r = mcs251_ld_direct8(c, dir8);
    uint8_t res = (uint8_t)(r - 1);
    mcs251_st_direct8(c, dir8, res);
    mcs251_logic8_flags(c, res);
    cond_branch(c, res != 0);
}

/* ------------------------------------------------------------------ */
/* XCH / XCHD                                                          */
/* ------------------------------------------------------------------ */

static void xchd(MCS251 *c, int i)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint8_t m = mcs251_ld_ri8(c, i);
    uint8_t a_new = (uint8_t)((a & 0xF0) | (m & 0x0F));
    uint8_t m_new = (uint8_t)((m & 0xF0) | (a & 0x0F));
    mcs251_st_reg8(c, RF_ACC, a_new);
    mcs251_st_ri8(c, i, m_new);
}

/* ------------------------------------------------------------------ */
/* MOVC / MOVX                                                         */
/* ------------------------------------------------------------------ */

static void do_movc(MCS251 *c, uint16_t base)
{
    uint8_t a = mcs251_ld_reg8(c, RF_ACC);
    uint16_t addr = (uint16_t)((base + a) & 0xFFFF);
    mcs251_st_reg8(c, RF_ACC, mcs251_ld_code8(c, addr));
}

static void movx_a(MCS251 *c, uint16_t addr)
{
    mcs251_st_reg8(c, RF_ACC, mcs251_ld_xram8(c, addr));
}

static void movx_a_dptr(MCS251 *c)
{
    movx_a(c, mcs251_ld_dptr(c));
}

static void movx_a_ri(MCS251 *c, int i)
{
    movx_a(c, mcs251_ld_reg8(c, i));
}

static void movx_dptr_a(MCS251 *c)
{
    mcs251_st_xram8(c, mcs251_ld_dptr(c), mcs251_ld_reg8(c, RF_ACC));
}

static void movx_ri_a(MCS251 *c, int i)
{
    mcs251_st_xram8(c, mcs251_ld_reg8(c, i), mcs251_ld_reg8(c, RF_ACC));
}

/* Decoder core (4 decoder functions, static). */
#include "decode_impl.inc"

/* Main dispatch: fetch opcode, decode, execute.  Returns machine cycles. */
int g_trace_asm = 0;
int g_op_stats = 0;
int g_cov_on = 0;          /* --coverage: 指令覆盖位图启用 (并入 features) */

/* 在 -sym 提供符号表时启用函数级行为跟踪 */
int g_trace_func = 0;

/* 合并追踪特性掩码: 启动时由 mcs251_update_trace_features() 从各全局量收拢。
 * 全部关闭时 execute_one 用单次分支跳过所有追踪开销。 */
int g_trace_features = 0;

enum {
    TF_ASM     = 1 << 0,   /* -d in_asm 指令迹 */
    TF_WATCH   = 1 << 1,   /* --trace-watch 写看门狗 */
    TF_OPSTATS = 1 << 2,   /* --op-stats 直方图 */
    TF_FUNC    = 1 << 3,   /* -sym 函数级行为跟踪 */
    TF_COV     = 1 << 4,   /* --coverage 覆盖位图 */
};

void mcs251_update_trace_features(void)
{
    int f = 0;
    if (g_trace_asm)        f |= TF_ASM;
    if (g_trace_watch >= 0) f |= TF_WATCH;
    if (g_op_stats)         f |= TF_OPSTATS;
    if (g_trace_func)       f |= TF_FUNC;
    if (g_cov_on)           f |= TF_COV;
    g_trace_features = f;
}

/* 二分查找 PC 所属函数 (sym 表按地址升序)。返回索引或 -1。
 * 快速路径: 顺序执行基本停留在一个函数内 (仅在 CALL/RET 跨界),
 * last_func_idx 缓存命中率≈100%, 免去 O(log n) 二分。 */
static int func_of_pc(MCS251 *c, uint16_t pc)
{
    int f = c->last_func_idx;
    if (f >= 0 && f < c->sym_n && c->syms[f].addr <= pc &&
        (f + 1 >= c->sym_n || c->syms[f + 1].addr > pc))
        return f;
    /* 仍在下界外 (startup 段): 免搜索 */
    if (f < 0 && c->sym_n > 0 && pc < c->syms[0].addr)
        return -1;
    int lo = 0, hi = c->sym_n - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (c->syms[mid].addr <= pc) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    c->last_func_idx = best;
    return best;
}

int mcs251_execute_one(MCS251 *c)
{
    uint8_t op0 = fetch_op8(c);              /* fetch + 逃逸检查并入取指 */
    uint16_t iaddr = (uint16_t)(c->pc - 1);   /* 当前指令地址 */
    uint8_t wv = 0;
    if (iaddr == 0x0D78)
        fprintf(stderr, "[SORT] cy=%llu arr=%04X %04X %04X %04X %04X %04X  raw=%02X %02X %02X %02X %02X %02X\n",
                (unsigned long long)c->cycles,
                mcs251_ld_mem16(c, 0x0048), mcs251_ld_mem16(c, 0x004A),
                mcs251_ld_mem16(c, 0x004C), mcs251_ld_mem16(c, 0x004E),
                mcs251_ld_mem16(c, 0x0050), mcs251_ld_mem16(c, 0x0052),
                c->iram[0x48], c->iram[0x49], c->iram[0x4A], c->iram[0x4B],
                c->iram[0x4C], c->iram[0x4D]);
    if (iaddr == 0x19E6 || iaddr == 0x19F7)
        fprintf(stderr, "[INID] iaddr=%04X cy=%llu DR0=%08X WR8=%04X WR4=%04X R11=%02X\n",
                iaddr, (unsigned long long)c->cycles,
                mcs251_ld_drk32(c, 0), mcs251_ld_wrj16(c, 8),
                mcs251_ld_wrj16(c, 4), mcs251_ld_reg8(c, 11));
    if (g_trace_features) {
        if (g_trace_watch >= 0)
            wv = c->iram[g_trace_watch];
        if (g_op_stats)
            c->op_stats[op0]++;
        if (g_trace_asm) {
            uint32_t pc = c->pc - 1;
            fprintf(stderr, "%04x: %02x  cy=%llu\n",
                    (unsigned)(pc & 0xFFFF), op0, (unsigned long long)c->cycles);
        }
    }
    /* 指令覆盖位图 */
    if ((g_trace_features & TF_COV) && c->cov_map
        && iaddr >= c->cov_lo && iaddr <= c->cov_hi)
        c->cov_map[(iaddr - c->cov_lo) / 8] |= (uint8_t)(1 << ((iaddr - c->cov_lo) % 8));
    /* 逃逸检测已并入 fetch_op8 (取指时对指令首地址检查), 此处不再重复。 */
    /* 函数级行为跟踪 (decode 前: 进入检测) */
    if ((g_trace_features & TF_FUNC) && !c->escaped) {
        int f = func_of_pc(c, iaddr);
        if (f >= 0 && f != c->cur_func) {
            if (c->cur_func >= 0) {
                /* 从另一函数切换来 → 记一次调用 (startup 的 LJMP 不算) */
                c->func_recs[f].calls++;
            }
            if (!c->func_recs[f].reached) {
                c->func_recs[f].reached = 1;
                c->func_recs[f].entry = c->syms[f].addr;
                c->func_recs[f].first_cy = c->cycles;
            }
            c->cur_func = f;
        }
    }
    /* 4 路分发: 实测 (MSVC/msys -O2) 原 if-else 链已被 gcc 编译成跳转表,
     * 比 256 项查表+switch/函数指针更快 (-10%); 保持原样, 不再合并。 */
    if (op0 == 0xA5)
        decode_a5(c);
    else if (op0 == 0xA9)
        decode_bit(c);
    else if (is_251_op(op0))
        decode_251(c, op0);
    else
        decode_8051(c, op0);
    /* RET/RETI/ERET 执行后 pc 已是返回地址: 记录返回目标 + 弹栈 + 一致性检查 */
    if (op0 == 0x22 || op0 == 0x32 || op0 == 0xAA) {
        int f = c->cur_func;
        if ((g_trace_features & TF_FUNC) && f >= 0 && f < c->sym_n
            && !c->func_recs[f].ret_done) {
            c->func_recs[f].ret_done = 1;
            c->func_recs[f].ret_to = c->pc;
        }
        /* RET 栈一致性: 返回地址必须曾被 push (CALL/中断入口)。
         * 仅当目标落在装载代码范围内 (code_lo..code_hi) 才算真违规
         * (链接 bug: ret→0x005E 类); 代码外 = Keil main 返回弹空栈/变量
         * 区 (startup LJMP 进 main, RET 弹垃圾 → 重启), 记 restart 不误报。 */
        if (!(c->ret_pushed[c->pc >> 3] & (1 << (c->pc & 7)))) {
            if (c->pc != 0 && c->code_hi
                && c->pc >= c->code_lo && c->pc <= c->code_hi) {
                if (!c->ret_mismatch) {
                    c->ret_mismatch_pc = c->pc;
                    c->ret_mismatch_src = iaddr;
                    c->ret_mismatch_sp = get_sp(c);
                    for (int k = 0; k < 6; k++)
                        c->ret_mismatch_stk[k] = mcs251_ld_iram8(c,
                            (uint16_t)(get_sp(c) - 5 + k));
                }
                c->ret_mismatch++;
            } else {
                c->restarts++;   /* main 返回 → 弹到代码外 → 重启 */
                if (c->restarts == 1)
                    c->restart_retval = mcs251_ld_wrj16(c, 6); /* 首次重启时 WR6 = main 返回值 */
            }
        }
        /* 自校正: 返回地址所属函数即调用者 (无需维护调用栈, 抗尾跳/中断) */
        if (g_trace_features & TF_FUNC)
            c->cur_func = func_of_pc(c, c->pc);
    }
    /* 写看门狗: 报告任何导致 iram[watch] 变化的指令 (含越界/别名) */
    if ((g_trace_features & TF_WATCH) && c->iram[g_trace_watch] != wv)
        fprintf(stderr, "[WATCH] iram[%02X] %02X -> %02X  instr@%04X op=%02X cy=%llu\n",
                g_trace_watch, wv, c->iram[g_trace_watch], iaddr, op0,
                (unsigned long long)c->cycles);
    return 1;   /* 1 machine cycle per instruction */
}
