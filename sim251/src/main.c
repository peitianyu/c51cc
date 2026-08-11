/*
 * main.c — MCS-251 standalone interpreter: CLI, run loop, dump_state.
 *
 * Usage: mcs251 [-machine mcs251] [-bios FIRMWARE] [-d cpu] [-D LOGFILE]
 *               [-display none] [--cycles N] [--dump-every N]
 *               [--run-list FILE]   (批处理: 单进程顺序执行多个固件)
 *
 * The -d/-D/-machine/-display options mirror QEMU's so the existing
 * tests/mcs251/run_tests.py harness can drive this emulator directly.
 *
 * --run-list FILE: 每行 <bios> <cycles> <dump> [--input F] [--serial F]
 *                  [--trace-watch ADDR] [--int0 N] [--int2 N] [--int3 N]
 *                  [--lvd N]; 每 run 独立 reset, 结果写各自 dump 文件,
 *                  stdout 逐行 "BATCH <idx> <rc>", 退出码=首个非 0。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "mcs251.h"

void mcs251_soc_cycle(MCS251 *c);   /* soc.c */

/* UART RX 注入缓冲 (--input): soc.c 每周期轮询。 */
uint8_t *g_rx_buf = NULL;
size_t g_rx_n = 0, g_rx_i = 0;
uint64_t g_rx_last_cy = 0;

/* 外部中断/LVD 激励注入 (--int0/--int2/--int3/--lvd, 周期数): */
uint64_t g_int0_cy = 0, g_int2_cy = 0, g_int3_cy = 0;
int      g_lvd_cy = -1;

/* ------------------------------------------------------------------ */
/* dump_state — byte-compatible with QEMU target/mcs251/cpu.c          */
/* ------------------------------------------------------------------ */
void mcs251_dump_state(MCS251 *c, FILE *f)
{
    int i;
    uint8_t bank = c->psw & (PSW_RS1 | PSW_RS0);

    fprintf(f, "\n");
    fprintf(f, "PC:      %04x\n", c->pc);
    fprintf(f, "SP:      %04x\n",
            c->rf[RF_SPX] | (c->rf[RF_SPX + 1] << 8));
    fprintf(f, "A:       %02x   B:    %02x\n",
            c->rf[RF_ACC], c->rf[RF_B]);
    fprintf(f, "PSW:     %02x   PSW1: %02x\n", c->psw, c->psw1);
    fprintf(f, "DPTR0:   %02x%02x   DPTR1: %02x%02x\n",
            c->dph0, c->dpl0, c->dph1, c->dpl1);
    /* STC32G I/O ports — STC32G12K128 SFR 布局与 8051 不同:
     * P0=0x80 P1=0x90 P2=0xA0 P3=0xB0 P4=0xC0 P5=0xC8 P6=0xE8 P7=0xF8
     * (官方 STC32G.H 定义; 传统 8051 的 P6=0xD0/P7=0xE8 不适用于 STC32G). */
    fprintf(f, "PORTS:  P0=%02x P1=%02x P2=%02x P3=%02x P4=%02x P5=%02x P6=%02x P7=%02x\n",
            c->sfr[0x00], c->sfr[0x10], c->sfr[0x20], c->sfr[0x30],
            c->sfr[0x40], c->sfr[0x48], c->sfr[0x68], c->sfr[0x78]);

    fprintf(f, "\n");
    for (i = 0; i < 16; i++) {
        uint8_t v = (i < 8) ? c->iram[bank + i] : c->rf[i];
        fprintf(f, "R[%02d]:  %02x   ", i, v);
        if ((i % 8) == 7)
            fprintf(f, "\n");
    }
    /* 返回值协议: C251 返回值 = R6(高):R7(低); run_suite 解析 WR6= 后字节交换 */
    fprintf(f, "WR6=%02x%02x\n", c->iram[bank + 7], c->iram[bank + 6]);
    /* 临时调试: 栈顶区域 (局部变量) */
    {
        int sp = c->rf[RF_SPX] | (c->rf[RF_SPX + 1] << 8);
        fprintf(f, "SP=%04X STK:", sp);
        for (int k = sp - 16; k < sp + 8; k++) {
            if (k >= 0 && k < MCS251_IRAM_SIZE)
                fprintf(f, " %02X", c->iram[k]);
            else
                fprintf(f, " --");
        }
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
    fflush(f);
}

/* ------------------------------------------------------------------ */
/* Firmware loading (raw binary or Intel HEX)                          */
/* ------------------------------------------------------------------ */

/* Hex digit -> 0..15, or -1. */
static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9')  return ch - '0';
    if (ch >= 'A' && ch <= 'F')  return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')  return ch - 'a' + 10;
    return -1;
}

/* Load an Intel HEX stream into code space.  Handles record types
 * 00 (data), 01 (EOF), 02 (extended segment) and 04 (extended linear). */
static int load_hex(MCS251 *c, FILE *f)
{
    char line[1024];
    unsigned long base = 0;
    int base_seen = 0;          /* 显式扩展地址记录 (type 02/04) 是否出现 */
    int nrec = 0;

    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (*p != ':')
            continue;           /* skip non-record lines */
        p++;

        /* :LLAAAATT<data>CC */
        unsigned cnt = 0, addr = 0, type = 0, sum = 0, cksum = 0;
        int h;
        /* byte count LL */
        h = hexval(p[0]); if (h < 0) return -1; cnt = (unsigned)h; p++;
        h = hexval(p[0]); if (h < 0) return -1; cnt = (cnt << 4) | (unsigned)h; p++;
        sum += cnt;
        /* 16-bit address AAAA */
        for (int i = 0; i < 4; i++) {
            h = hexval(*p++); if (h < 0) return -1;
            addr = (addr << 4) | (unsigned)h;
        }
        sum += (addr >> 8) & 0xFF;
        sum += addr & 0xFF;
        /* record type TT */
        h = hexval(p[0]); if (h < 0) return -1; type = (unsigned)h; p++;
        h = hexval(p[0]); if (h < 0) return -1; type = (type << 4) | (unsigned)h; p++;
        sum += type;
        /* payload data */
        unsigned char data[256];
        for (unsigned i = 0; i < cnt; i++) {
            int h0 = hexval(p[0]), h1 = hexval(p[1]);
            if (h0 < 0 || h1 < 0) return -1;
            data[i] = (unsigned char)((h0 << 4) | h1);
            p += 2;
            sum += data[i];
        }
        /* checksum CC */
        h = hexval(p[0]); if (h < 0) return -1; cksum = (unsigned)h; p++;
        h = hexval(p[0]); if (h < 0) return -1; cksum = (cksum << 4) | (unsigned)h; p++;
        if (((sum + cksum) & 0xFF) != 0)
            return -1;          /* bad checksum */

        switch (type) {
        case 0x00: {            /* data */
            unsigned long a = base + addr;
            /* C251/STC32G: 代码区 bits 16-23=0xFF (TCC: 0x00FFxxxx,
               Keil ref: 0xFFxxxxxx) → c->code[0..64K];
               edata bits 16-23=0x00 → c->iram[0..64K];
               XRAM bits 16-23=0x01 → c->xram[0..64K]。
               裸低地址 (未出现 type 02/04 扩展地址记录) 按经典
               8051/Keil base-0 模型默认映射代码区, 只有显式
               edata 基址标记 (type-04 = 0x0000) 才路由 IRAM。 */
            if ((a >> 24) == 0xFF || (a & 0xFF0000u) == 0xFF0000u) {
                a &= 0xFFFF;
                for (unsigned i = 0; i < cnt; i++)
                    if (a + i < MCS251_CODE_SIZE) {
                        c->code[a + i] = data[i];
                        if (a + i < c->code_lo) c->code_lo = a + i;
                        if (a + i > c->code_hi) c->code_hi = a + i;
                    }
            } else if (!base_seen) {
                /* 裸低地址: 无扩展地址记录 → 默认代码区 (base-0) */
                for (unsigned i = 0; i < cnt; i++)
                    if (a + i < MCS251_CODE_SIZE) {
                        c->code[a + i] = data[i];
                        if (a + i < c->code_lo) c->code_lo = a + i;
                        if (a + i > c->code_hi) c->code_hi = a + i;
                    }
            } else if (a < MCS251_IRAM_SIZE) {
                /* 显式 edata 0x00xxxx → IRAM */
                for (unsigned i = 0; i < cnt; i++)
                    if (a + i < MCS251_IRAM_SIZE)
                        c->iram[a + i] = data[i];
            } else if ((a >> 24) == 0x01 || (a & 0xFF0000u) == 0x010000u) {
                a &= 0xFFFF;
                for (unsigned i = 0; i < cnt; i++)
                    if (a + i < MCS251_XRAM_SIZE)
                        c->xram[a + i] = data[i];
            }
            nrec++;
            break; }
        case 0x01:              /* EOF */
            return nrec > 0 ? 0 : -1;
        case 0x02:              /* extended segment address */
            base = (unsigned long)((data[0] << 8) | data[1]) << 4;
            base_seen = 1;
            break;
        case 0x04:              /* extended linear address */
            base = (unsigned long)((data[0] << 8) | data[1]) << 16;
            base_seen = 1;
            break;
        default:                /* ignore other record types */
            break;
        }
    }
    return nrec > 0 ? 0 : -1;
}

/* Auto-detect Intel HEX (first non-whitespace byte is ':') vs raw binary. */
int mcs251_load_bin(MCS251 *c, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    int first = fgetc(f);
    if (first == ':') {
        ungetc(first, f);
        int rc = load_hex(c, f);
        fclose(f);
        return rc;
    }
    if (first != EOF)
        c->code[0] = (uint8_t)first;
    size_t n = 1 + fread(c->code + 1, 1, MCS251_CODE_SIZE - 1, f);
    fclose(f);
    if (n > 0) { c->code_lo = 0; c->code_hi = n - 1; }
    return n > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* 运行核心 (单次执行 + 状态导出) — 单进程与 --run-list 批处理共用,     */
/* 保证两者行为逐字节一致。                                            */
/* ------------------------------------------------------------------ */

static void run_loop(MCS251 *cpu, uint64_t max_cycles, uint64_t dump_every,
                     FILE *logf)
{
    uint64_t next_dump = dump_every;
    while (cpu->cycles < max_cycles && !cpu->escaped && !cpu->restarts) {
        if (cpu->irq_requested)
            mcs251_poll_interrupt(cpu);
        mcs251_execute_one(cpu);
        cpu->cycles++;
        mcs251_soc_cycle(cpu);
        if (logf && cpu->cycles >= next_dump) {
            mcs251_dump_state(cpu, logf);
            next_dump += dump_every;
        }
    }
    if (!cpu->escaped && cpu->cycles >= max_cycles)
        cpu->hit_cycle_limit = 1;
}

/* 全状态导出 (--dump-ram): 供功能测试验证任意内存/SFR/XFR 值。
 * 文本格式每行: 键:值 或 ADDR=VALUE (全大写 hex)。 */
static void write_dumpram(MCS251 *cpu, const char *dumpram)
{
    if (!dumpram)
        return;
    FILE *df = fopen(dumpram, "w");
    if (!df)
        return;
    fprintf(df, "PC=%04X\n", cpu->pc);
    fprintf(df, "SP=%04X\n",
            cpu->rf[RF_SPX] | (cpu->rf[RF_SPX + 1] << 8));
    fprintf(df, "PSW=%02X\n", cpu->psw);
    fprintf(df, "PSW1=%02X\n", cpu->psw1);
    fprintf(df, "CYCLES=%llu\n", (unsigned long long)cpu->cycles);
    for (int i = 0; i < 16; i++)
        fprintf(df, "R%02X=%02X\n", i, mcs251_ld_reg8(cpu, i));
    fprintf(df, "[IRAM]\n");
    /* EDATA 已扩到 64KB: 只打印非零, 未打印地址解析默认 0 */
    for (int a = 0; a < MCS251_IRAM_SIZE; a++)
        if (cpu->iram[a])
            fprintf(df, "%04X=%02X\n", a, cpu->iram[a]);
    fprintf(df, "[SFR]\n");
    for (int i = 0; i < MCS251_SFR_SIZE; i++)
        fprintf(df, "%02X=%02X\n", 0x80 + i, cpu->sfr[i]);
    fprintf(df, "[XFR]\n");
    for (int i = 0; i < MCS251_XFR_SIZE; i++)
        fprintf(df, "%04X=%02X\n", MCS251_XFR_LO + i, cpu->xfr[i]);
    fprintf(df, "[XRAM]\n");
    for (int a = 0; a < MCS251_XRAM_SIZE; a++)
        if (cpu->xram[a])
            fprintf(df, "%04X=%02X\n", a, cpu->xram[a]);
    fclose(df);
}

/* 退出码: 0=clean, 1=escaped, 2=timeout, 3=violation.
 * Keil main 返回 → 弹空栈/变量重启 (restarts>0) 是固有行为,
 * 其后的跑飞不算真逃逸。 */
static int run_exit_code(const MCS251 *cpu)
{
    if (cpu->escaped && !cpu->restarts)
        return 1;
    if (cpu->ret_mismatch)
        return 3;
    return cpu->hit_cycle_limit ? 2 : 0;
}

/* ------------------------------------------------------------------ */
/* --run-list 批处理模式: 单进程顺序执行多个固件 (测试基础设施提速,   */
/* 免去每用例一次进程启动)。                                          */
/* 文件每行 (空白分隔): <bios> <cycles> <dump> [--input F] [--serial F] */
/*   [--trace-watch ADDR] [--int0 N] [--int2 N] [--int3 N] [--lvd N]   */
/* 每个 run 独立 mcs251_reset; 结果写各自 dump 文件; stdout 逐行       */
/* 打印 "BATCH <idx> <rc>" 供 harness 映射每用例退出码。               */
/* 返回: 首个非 0 退出码 (0=全部 clean)。                             */
static int run_batch(MCS251 *cpu, const char *listpath)
{
    FILE *f = fopen(listpath, "r");
    if (!f) {
        fprintf(stderr, "mcs251: cannot open run-list %s\n", listpath);
        return 2;
    }
    char line[8192];
    int idx = 0, agg = 0;
    while (fgets(line, sizeof line, f)) {
        /* 简单空白分词 (测试路径不含空格) */
        char *tok[96];
        int nt = 0;
        char *p = line;
        for (;;) {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (!*p || nt >= 96) break;
            tok[nt++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
            if (*p) *p++ = '\0';
        }
        if (nt < 3) continue;                    /* 空行/畸形行跳过 */
        const char *bios = tok[0];
        uint64_t cycles = strtoull(tok[1], NULL, 10);
        const char *dump = tok[2];
        const char *input = NULL, *serial = NULL;
        uint64_t int0 = 0, int2 = 0, int3 = 0;
        int lvd = -1;
        g_trace_watch = -1;
        for (int i = 3; i + 1 < nt; i += 2) {
            if      (!strcmp(tok[i], "--input"))       input  = tok[i + 1];
            else if (!strcmp(tok[i], "--serial"))      serial = tok[i + 1];
            else if (!strcmp(tok[i], "--trace-watch")) g_trace_watch = (int)strtol(tok[i+1], NULL, 0);
            else if (!strcmp(tok[i], "--int0"))        int0 = strtoull(tok[i+1], NULL, 0);
            else if (!strcmp(tok[i], "--int2"))        int2 = strtoull(tok[i+1], NULL, 0);
            else if (!strcmp(tok[i], "--int3"))        int3 = strtoull(tok[i+1], NULL, 0);
            else if (!strcmp(tok[i], "--lvd"))         lvd  = (int)strtol(tok[i+1], NULL, 0);
            else fprintf(stderr, "mcs251: run-list unknown option %s (ignored)\n", tok[i]);
        }
        /* 每 run 独立 CPU 状态 (reset 已设 int0_cycles=1000/lvd=-1) */
        mcs251_reset(cpu);
        if (int0) cpu->int0_cycles = int0;
        if (int2) cpu->int2_cycles = int2;
        if (int3) cpu->int3_cycles = int3;
        if (lvd >= 0) cpu->lvd_cy = lvd;
        if (g_rx_buf) { free(g_rx_buf); g_rx_buf = NULL; g_rx_n = g_rx_i = 0; }
        if (input) {
            FILE *if_ = fopen(input, "rb");
            if (if_) {
                uint8_t ibuf[4096];
                size_t n = fread(ibuf, 1, sizeof ibuf, if_);
                fclose(if_);
                g_rx_buf = malloc(n ? n : 1);
                memcpy(g_rx_buf, ibuf, n);
                g_rx_n = n; g_rx_i = 0;
            }
        }
        if (cpu->serial_out) { fclose(cpu->serial_out); cpu->serial_out = NULL; }
        if (serial) {
            cpu->serial_out = fopen(serial, "wb");
            if (!cpu->serial_out)
                fprintf(stderr, "mcs251: cannot open serial output %s\n", serial);
        }
        if (mcs251_load_bin(cpu, bios) != 0) {
            fprintf(stderr, "mcs251: cannot load firmware %s\n", bios);
            printf("BATCH %d 2\n", idx++);
            if (!agg) agg = 2;
            continue;
        }
        mcs251_update_trace_features();
        run_loop(cpu, cycles, 0, NULL);
        write_dumpram(cpu, dump);
        int rc = run_exit_code(cpu);
        printf("BATCH %d %d\n", idx, rc);
        idx++;
        if (!agg && rc) agg = rc;
    }
    if (g_rx_buf) { free(g_rx_buf); g_rx_buf = NULL; g_rx_n = g_rx_i = 0; }
    if (cpu->serial_out) { fclose(cpu->serial_out); cpu->serial_out = NULL; }
    fclose(f);
    return agg;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static int sym_cmp(const void *pa, const void *pb)
{
    const struct SymEntry *a = pa, *b = pb;
    return (a->addr > b->addr) - (a->addr < b->addr);
}
int main(int argc, char **argv)
{
    MCS251 cpu;
    const char *bios = NULL;
    const char *logpath = NULL;
    const char *sympath = NULL;
    const char *sfrtrace = NULL;
    const char *xfrtrace = NULL;
    const char *covfile = NULL;
    const char *input = NULL;
    const char *serial = NULL;
    const char *dumpram = NULL;
    const char *runlist = NULL;
    FILE *logf = stdout;
    uint64_t max_cycles = 2000000;
    uint64_t dump_every = 50000;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-bios") && i + 1 < argc)      bios = argv[++i];
        else if (!strcmp(a, "-D") && i + 1 < argc)    logpath = argv[++i];
        else if (!strcmp(a, "--cycles") && i+1 < argc) max_cycles = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--dump-every") && i+1 < argc) dump_every = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--op-stats")) g_op_stats = 1;
        else if (!strcmp(a, "--trace-stack")) g_trace_stack = 1;
        else if (!strcmp(a, "--trace-stkwr")) g_trace_stkwr = 1;
        else if (!strcmp(a, "--trace-watch") && i + 1 < argc) g_trace_watch = (int)strtol(argv[++i], NULL, 0);
        else if (!strcmp(a, "--dump-ram") && i + 1 < argc) dumpram = argv[++i];
        else if (!strcmp(a, "--run-list") && i + 1 < argc) runlist = argv[++i];
        else if (!strcmp(a, "-sym") && i + 1 < argc)  sympath = argv[++i];
        else if (!strcmp(a, "--trace-sfr") && i + 1 < argc) sfrtrace = argv[++i];
        else if (!strcmp(a, "--trace-xfr") && i + 1 < argc) xfrtrace = argv[++i];
        else if (!strcmp(a, "--coverage") && i + 1 < argc) covfile = argv[++i];
        else if (!strcmp(a, "--input") && i + 1 < argc) input = argv[++i];
        else if (!strcmp(a, "--serial") && i + 1 < argc) serial = argv[++i];
        else if (!strcmp(a, "--int0") && i + 1 < argc) g_int0_cy = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(a, "--int2") && i + 1 < argc) g_int2_cy = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(a, "--int3") && i + 1 < argc) g_int3_cy = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(a, "--lvd") && i + 1 < argc) g_lvd_cy = (int)strtol(argv[++i], NULL, 0);
        else if (!strcmp(a, "-d") && i + 1 < argc) {
            /* QEMU-compat: enable instruction trace for `-d in_asm`. */
            if (strstr(argv[i + 1], "in_asm"))
                g_trace_asm = 1;
            i++;
        }
        /* Silently ignore other QEMU-compat options. */
    }

    /* 批处理模式: 单进程顺序执行 run-list 中多个固件 (测试基础设施提速) */
    if (runlist)
        return run_batch(&cpu, runlist);

    mcs251_reset(&cpu);
    cpu.code_lo = MCS251_CODE_SIZE;   /* 装载时记录实际代码范围 */
    /* 外部中断/LVD 激励覆盖 reset 默认 (默认 0 = 不覆盖) */
    if (g_int0_cy) cpu.int0_cycles = g_int0_cy;
    if (g_int2_cy) cpu.int2_cycles = g_int2_cy;
    if (g_int3_cy) cpu.int3_cycles = g_int3_cy;
    if (g_lvd_cy >= 0) cpu.lvd_cy = g_lvd_cy;
    if (bios) {
        if (mcs251_load_bin(&cpu, bios) != 0) {
            fprintf(stderr, "mcs251: cannot load firmware %s\n", bios);
            return 2;
        }
    }
    /* 函数符号表 (-sym): 启用函数级行为跟踪 */
    if (sympath) {
        FILE *sf = fopen(sympath, "r");
        if (sf) {
            char line[128];
            int cap = 64, n = 0;
            cpu.syms = malloc(cap * sizeof(*cpu.syms));
            while (fgets(line, sizeof line, sf)) {
                unsigned a;
                char nm[64];
                if (sscanf(line, "%x\t%63s", &a, nm) == 2) {
                    if (n >= cap) { cap *= 2; cpu.syms = realloc(cpu.syms, cap * sizeof(*cpu.syms)); }
                    cpu.syms[n].addr = (uint16_t)a;
                    cpu.syms[n].name = strdup(nm);
                    n++;
                }
            }
            fclose(sf);
            if (n > 1)
                qsort(cpu.syms, n, sizeof(*cpu.syms), sym_cmp);   /* 防御: 保证二分查找升序 */
            cpu.sym_n = n;
            cpu.func_recs = calloc(n, sizeof(*cpu.func_recs));    /* 与 syms 同尺寸, 无 64 上限 */
            if (n) g_trace_func = 1;
        }
    }
    /* SFR 写日志缓冲 */
    if (sfrtrace) {
        cpu.sfr_trace_cap = 1 << 20;
        cpu.sfr_trace = malloc(cpu.sfr_trace_cap * sizeof(*cpu.sfr_trace));
        cpu.sfr_trace_n = 0;
    }
    if (xfrtrace) {
        cpu.xfr_trace_cap = 1 << 20;
        cpu.xfr_trace = malloc(cpu.xfr_trace_cap * sizeof(*cpu.xfr_trace));
        cpu.xfr_trace_n = 0;
    }
    /* 指令覆盖位图 */
    if (covfile) {
        cpu.cov_lo = 0;
        cpu.cov_hi = MCS251_CODE_SIZE - 1;
        cpu.cov_map = calloc((MCS251_CODE_SIZE + 7) / 8, 1);
        g_cov_on = 1;
    }
    if (logpath) {
        logf = fopen(logpath, "w");
        if (!logf) {
            fprintf(stderr, "mcs251: cannot open log %s\n", logpath);
            return 2;
        }
    }
    /* UART 输出: --serial FILE (多路 UART 共用, 逐字节) */
    if (serial) {
        cpu.serial_out = fopen(serial, "wb");
        if (!cpu.serial_out) {
            fprintf(stderr, "mcs251: cannot open serial output %s\n", serial);
            return 2;
        }
    }
    /* UART RX 注入: --input FILE (字节流 → UART1 RX, 每 800 周期 1 字节) */
/* UART RX 注入 (--input): 每 800 周期注 1 字节到 UART1.
 * 延迟注入: 模拟真实场景 (PC 在 MCU 完成 UART 初始化后才发数据),
 * 避免慢启动固件 (TCC) 在初始化前丢失全部注入。 */
    if (input) {
        FILE *if_ = fopen(input, "rb");
        if (if_) {
            uint8_t ibuf[4096];
            size_t n = fread(ibuf, 1, sizeof ibuf, if_);
            fclose(if_);
            g_rx_buf = malloc(n ? n : 1);
            memcpy(g_rx_buf, ibuf, n);
            g_rx_n = n; g_rx_i = 0;
            g_rx_last_cy = 20000;   /* 延迟注入起点 (周期) */
        }
    }

    /* 全部追踪开关已配置完成: 收拢为单一 features 掩码 (execute 热路径用) */
    mcs251_update_trace_features();

    /* Run with periodic dumps so the harness sees the final state. */
    run_loop(&cpu, max_cycles, dump_every, logf);
    mcs251_dump_state(&cpu, logf);

    /* 全状态导出 (--dump-ram): 供功能测试验证任意内存/SFR/XFR 值。 */
    write_dumpram(&cpu, dumpram);

    /* 函数级行为报告 (依赖 -sym) */
    if (g_trace_func) {
        fprintf(logf, "\nFUNC-TRACE (%d syms):\n", cpu.sym_n);
        for (int f = 0; f < cpu.sym_n; f++) {
            const MCS251 *S = &cpu;
            if (S->func_recs[f].reached) {
                char rb[8];
                if (S->func_recs[f].ret_done)
                    snprintf(rb, sizeof rb, "%04X", S->func_recs[f].ret_to);
                else
                    snprintf(rb, sizeof rb, "----");   /* 从未 RET (死循环) */
                fprintf(logf, "  %-28s entry=%04X cy=%llu wr=%u call=%u ret=%s\n",
                        S->syms[f].name, S->func_recs[f].entry,
                        (unsigned long long)S->func_recs[f].first_cy,
                        S->func_recs[f].sfr_writes, S->func_recs[f].calls, rb);
            }
        }
    }

    if (g_op_stats) {
        fprintf(logf, "\nOP-STATS (top 40):\n");
        int idx[256];
        for (int i = 0; i < 256; i++) idx[i] = i;
        for (int i = 0; i < 256; i++)
            for (int j = i + 1; j < 256; j++)
                if (cpu.op_stats[idx[j]] > cpu.op_stats[idx[i]]) {
                    int t = idx[i]; idx[i] = idx[j]; idx[j] = t;
                }
        for (int k = 0; k < 40 && k < 256; k++) {
            int o = idx[k];
            if (cpu.op_stats[o])
                fprintf(logf, "  %02X: %llu\n", o, (unsigned long long)cpu.op_stats[o]);
        }
    }

    if (logf != stdout)
        fclose(logf);

    /* 逃逸报告 + SFR 日志 + 覆盖位图输出 */
    if (cpu.escaped)
        fprintf(stderr, "ESCAPED: pc=%04X (src=%04X) cy=%llu\n",
                cpu.escape_pc, cpu.escape_src,
                (unsigned long long)cpu.cycles);
    if (cpu.ret_mismatch)
        fprintf(stderr, "RET-MISMATCH: %u 次 RET 目标在代码内但从未被 push (首个 RET@%04X->%04X SP=%04X 栈顶=%02X %02X %02X %02X %02X %02X) cy=%llu\n",
                (unsigned)cpu.ret_mismatch, cpu.ret_mismatch_src, cpu.ret_mismatch_pc,
                cpu.ret_mismatch_sp,
                cpu.ret_mismatch_stk[0], cpu.ret_mismatch_stk[1], cpu.ret_mismatch_stk[2],
                cpu.ret_mismatch_stk[3], cpu.ret_mismatch_stk[4], cpu.ret_mismatch_stk[5],
                (unsigned long long)cpu.cycles);
    if (cpu.restarts)
        fprintf(stderr, "RESTART: %u 次 main 返回重启 (RET 目标在代码外, 非违规)\n",
                (unsigned)cpu.restarts);
    if (sfrtrace && cpu.sfr_trace) {
        FILE *tf = fopen(sfrtrace, "w");
        if (tf) {
            for (int i = 0; i < cpu.sfr_trace_n; i++)
                fprintf(tf, "%llu %02X %02X\n",
                        (unsigned long long)cpu.sfr_trace[i].cy,
                        cpu.sfr_trace[i].dir8, cpu.sfr_trace[i].val);
            fclose(tf);
        }
    }
    if (xfrtrace && cpu.xfr_trace) {
        FILE *tf = fopen(xfrtrace, "w");
        if (tf) {
            for (int i = 0; i < cpu.xfr_trace_n; i++)
                fprintf(tf, "%llu %04X %02X\n",
                        (unsigned long long)cpu.xfr_trace[i].cy,
                        cpu.xfr_trace[i].addr, cpu.xfr_trace[i].val);
            fclose(tf);
        }
    }
    if (covfile && cpu.cov_map) {
        FILE *cf = fopen(covfile, "w");
        if (cf) {
            for (uint64_t a = cpu.cov_lo; a <= cpu.cov_hi; a++)
                if (cpu.cov_map[(a - cpu.cov_lo) / 8] & (1 << ((a - cpu.cov_lo) % 8)))
                    fprintf(cf, "%04llx\n", (unsigned long long)a);
            fclose(cf);
        }
    }
    /* 退出码: 0=clean, 1=escaped, 2=timeout, 3=violation.
     * Keil main 返回 → 弹空栈/变量重启 (restarts>0) 是固有行为,
     * 其后的跑飞不算真逃逸。 */
    return run_exit_code(&cpu);
}
