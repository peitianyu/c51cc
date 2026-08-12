#include "c251_isel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void wr_name(char *buf, size_t n, int wr) {
    snprintf(buf, n, "WR%d", wr);
}

void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2) {
    if (!isel || !op) return;
    AsmInstr *ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup(op);
    ai->args = make_list();
    if (arg1) list_push(ai->args, strdup(arg1));
    if (arg2) list_push(ai->args, strdup(arg2));
    list_push(isel->sec->asminstrs, ai);
}

int isel_value_reg(C251GenContext* ctx, ValueName val) {
    if (!ctx || val < 0) return -1;
    char *k = c251_key(val);
    int *r = (int*)dict_get(ctx->value_to_reg, k);
    free(k);
    return r ? *r : -1;
}

/* obj 中是否已存在同名符号（全局变量/已分配的局部槽） */
static int c251_obj_has_sym(ObjFile *obj, const char *name) {
    if (!obj || !name) return 0;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *s = iter_next(&it);
        if (s && s->name && strcmp(s->name, name) == 0) return 1;
    }
    return 0;
}

/* ============================================================
 * 简单 liveness（M2）：
 *  - global_live：跨块活值（PHI 参数 / 出现在 ≥2 块）永不释放
 *  - 块内：从当前位置 pos（含）往后无使用 → 可释放
 * ============================================================ */

typedef struct LiveInfo { int cnt; int last_block; } LiveInfo;

/* 预扫描（isel_function）：统计每个值出现的不同块数；PHI 参数强制跨块活 */
static Dict* compute_global_live(Func* func) {
    Dict *d = make_dict(NULL);
    int block_id = 0;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block *blk = iter_next(&bit);
        /* 块内指令 args 使用 */
        for (Iter iit = list_iter(blk->instrs); !iter_end(iit);) {
            Instr *ins = iter_next(&iit);
            if (!ins || !ins->args) continue;
            for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
                ValueName *ap = iter_next(&ait);
                if (!ap || *ap < 0) continue;
                char *k = c251_key(*ap);
                LiveInfo *li = (LiveInfo*)dict_get(d, k);
                if (!li) { li = calloc(1, sizeof(LiveInfo)); li->last_block = -1; dict_put(d, k, li); }
                else free(k);
                if (li->last_block != block_id) { li->last_block = block_id; li->cnt++; }
            }
            /* 块内指令 dest 定义：定义块+使用块 ≥2 → 跨块活（防跨块值被死值释放） */
            if (ins->dest >= 0) {
                char *k = c251_key(ins->dest);
                LiveInfo *li = (LiveInfo*)dict_get(d, k);
                if (!li) { li = calloc(1, sizeof(LiveInfo)); li->last_block = -1; dict_put(d, k, li); }
                else free(k);
                if (li->last_block != block_id) { li->last_block = block_id; li->cnt++; }
            }
        }
        /* PHI 参数：无条件跨块活（cnt=2 哨兵） */
        for (Iter pit = list_iter(blk->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (!phi || !phi->args) continue;
            for (Iter ait = list_iter(phi->args); !iter_end(ait);) {
                ValueName *ap = iter_next(&ait);
                if (!ap || *ap < 0) continue;
                char *k = c251_key(*ap);
                LiveInfo *li = (LiveInfo*)dict_get(d, k);
                if (!li) { li = calloc(1, sizeof(LiveInfo)); li->cnt = 2; dict_put(d, k, li); }
                else { li->cnt = 2; free(k); }
            }
        }
        block_id++;
    }
    return d;
}

static bool is_global_live(Dict *gl, ValueName v) {
    if (!gl || v < 0) return false;
    char *k = c251_key(v);
    LiveInfo *li = (LiveInfo*)dict_get(gl, k);
    free(k);
    return li && li->cnt >= 2;
}

/* 值 v 在位置 pos（含）之后是否仍被使用 */
static bool value_still_used(ISelContext* isel, ValueName v, int pos) {
    if (v < 0) return false;
    if (is_global_live(isel->global_live, v)) return true;
    for (int i = pos; i < isel->block_instr_count; i++) {
        Instr *ins = isel->block_instrs[i];
        if (!ins || !ins->args) continue;
        for (Iter it = list_iter(ins->args); !iter_end(it);) {
            ValueName *ap = iter_next(&it);
            if (ap && *ap == v) return true;
        }
    }
    return false;
}

/* 选临时寄存器：避开 avoid1/avoid2 → 空闲 → 块内死值 → 强制溢出兜底（几乎不达） */
static int isel_temp_wr(ISelContext* isel, int avoid1, int avoid2) {
    C251GenContext *ctx = isel->ctx;
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        if (isel->reg_val[w/2] < 0) return w;
    }
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        ValueName rv = isel->reg_val[w/2];
        if (rv >= 0 && !value_still_used(isel, rv, isel->block_instr_pos)) return w;
    }
    /* 极端兜底：强制溢出第一个非 avoid 寄存器中的值 */
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        ValueName rv = isel->reg_val[w/2];
        if (rv >= 0) {
            char *sp = c251_alloc_spill(ctx, rv);
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), w);
            isel_emit(isel, "MOV", sp, wbuf);
            char *k = c251_key(rv);
            dict_remove(ctx->value_to_reg, k);
            free(k);
            isel->reg_val[w/2] = -1;
            return w;
        }
    }
    return 0; /* 理论不可达 */
}

/* 值 → 寄存器分配：已分配复用 → 空闲 → 块内死值释放 → -1（调用方走溢出） */
int isel_alloc_wr(ISelContext* isel, ValueName val) {
    C251GenContext *ctx = isel->ctx;
    char *key = c251_key(val);
    int *exist = (int*)dict_get(ctx->value_to_reg, key);
    if (exist) { free(key); return *exist; }

    int pos = isel->block_instr_pos;
    int w = -1;
    for (int i = 0; i < 4; i++)
        if (isel->reg_val[i] < 0) { w = i * 2; break; }
    if (w < 0) {
        for (int i = 0; i < 4; i++) {
            ValueName rv = isel->reg_val[i];
            if (rv >= 0 && !value_still_used(isel, rv, pos)) { w = i * 2; break; }
        }
    }
    if (w < 0) { free(key); return -1; }

    isel->reg_val[w/2] = val;
    int *slot = malloc(sizeof(int)); *slot = w;
    dict_put(ctx->value_to_reg, key, slot);
    return w;
}

/* WR w 覆盖的字节 (w, w+1) 是否命中 abi_bytes 中任一字节（大端 16 位布局: w=高字节） */
static int wr_conflicts_abi(int w, const int *bytes, int n) {
    for (int j = 0; j < n; j++)
        if (bytes[j] == w || bytes[j] == w + 1) return 1;
    return 0;
}

/* 选临时寄存器（额外避让 abi 字节）：同 isel_temp_wr（空闲 → 块内死值 → 强制溢出），
 * 每层多 wr_conflicts_abi 检查，防覆写未消费的 ABI 参数槽。 */
static int isel_temp_wr_avoid_bytes(ISelContext* isel, int avoid1, int avoid2,
                                    const int *bytes, int n) {
    C251GenContext *ctx = isel->ctx;
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        if (wr_conflicts_abi(w, bytes, n)) continue;
        if (isel->reg_val[w/2] < 0) return w;
    }
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        if (wr_conflicts_abi(w, bytes, n)) continue;
        ValueName rv = isel->reg_val[w/2];
        if (rv >= 0 && !value_still_used(isel, rv, isel->block_instr_pos)) return w;
    }
    /* 极端兜底：强制溢出第一个非 avoid 且不冲突寄存器中的值 */
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        if (wr_conflicts_abi(w, bytes, n)) continue;
        ValueName rv = isel->reg_val[w/2];
        if (rv >= 0) {
            char *sp = c251_alloc_spill(ctx, rv);
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), w);
            isel_emit(isel, "MOV", sp, wbuf);
            char *k = c251_key(rv);
            dict_remove(ctx->value_to_reg, k);
            free(k);
            isel->reg_val[w/2] = -1;
            return w;
        }
    }
    return 0; /* 理论不可达 */
}

/* 分配 WR 目标，避开 abi_bytes（其他参数的 ABI 槽，防覆写未消费参数）；
 * 逻辑同 isel_alloc_wr（空闲优先 → 块内死值释放），多一层字节冲突检查。 */
static int isel_alloc_wr_avoid(ISelContext* isel, ValueName val, const int *bytes, int n) {
    C251GenContext *ctx = isel->ctx;
    char *key = c251_key(val);
    int *exist = (int*)dict_get(ctx->value_to_reg, key);
    if (exist) { free(key); return *exist; }
    int pos = isel->block_instr_pos;
    int w = -1;
    for (int i = 0; i < 4; i++) {
        int ww = i * 2;
        if (isel->reg_val[i] >= 0) continue;
        if (wr_conflicts_abi(ww, bytes, n)) continue;
        w = ww; break;
    }
    if (w < 0) for (int i = 0; i < 4; i++) {
        int ww = i * 2;
        ValueName rv = isel->reg_val[i];
        if (rv < 0 || value_still_used(isel, rv, pos)) continue;
        if (wr_conflicts_abi(ww, bytes, n)) continue;
        w = ww; break;
    }
    if (w < 0) { free(key); return -1; }
    isel->reg_val[w/2] = val;
    int *slot = malloc(sizeof(int)); *slot = w;
    dict_put(ctx->value_to_reg, key, slot);
    return w;
}

/* 查 ADDR 产物指向的全局符号名（无则 NULL） */
static char* value_to_addr_lookup(C251GenContext* ctx, ValueName val);

/* 把值 v 加载到寄存器 w：v 已在 w 跳过；否则按 寄存器/常量/溢出槽 顺序 */
static int load_value_to_wr(ISelContext* isel, ValueName v, int w) {
    C251GenContext *ctx = isel->ctx;
    char wbuf[16]; wr_name(wbuf, sizeof(wbuf), w);
    int r = isel_value_reg(ctx, v);
    if (r == w) return 0;
    if (r >= 0) { char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r); isel_emit(isel, "MOV", wbuf, rbuf); return 0; }
    char *k = c251_key(v);
    int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k);
    free(k);
    if (cv) {
        char imm[32]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFFFF);
        isel_emit(isel, "MOV", wbuf, imm);
        return 0;
    }
    /* ADDR 产物作为值（指针变量/传参/比较）：物化符号地址 → MOV WRj,#sym */
    char *asym = value_to_addr_lookup(ctx, v);
    if (asym) {
        char saddr[64]; snprintf(saddr, sizeof(saddr), "#%s", asym);
        isel_emit(isel, "MOV", wbuf, saddr);
        return 0;
    }
    char *sp = c251_value_spill(ctx, v);
    if (sp) { isel_emit(isel, "MOV", wbuf, sp); return 0; }
    fprintf(stderr, "c251 isel: 值 %d 无寄存器/常量/槽可加载\n", v);
    return -1;
}

/* 查 ADDR 产物指向的全局符号名（无则 NULL） */
static char* value_to_addr_lookup(C251GenContext* ctx, ValueName val) {
    if (!ctx || !ctx->value_to_addr) return NULL;
    char *k = c251_key(val);
    char *sym = (char*)dict_get(ctx->value_to_addr, k);
    free(k);
    return sym;
}

/* M3: 查 sfr/sbit 编码值 (低 8 位 = SFR 地址, bit16+ = 位号, -1 = sfr 整字节)。
 * 返回 1 且 *addr/*bit 置值; 非 sfr/sbit 返回 0。 */
static int sfr_lookup(C251GenContext *ctx, const char *sym, int *addr, int *bit) {
    if (!ctx || !ctx->sfr_addr || !sym || !addr) return 0;
    int *v = (int*)dict_get(ctx->sfr_addr, (char*)sym);
    if (!v) return 0;
    *addr = (*v) & 0xFF;
    *bit = (*v) >> 16;
    if (*bit == 0xFFFF) *bit = -1;
    return 1;
}

/* 从 SSA 指令取 src1/src2 值名 */
static ValueName src1_of(Instr* ins) {
    if (!ins->args || list_len(ins->args) < 1) return -1;
    return *(ValueName*)list_get(ins->args, 0);
}
static ValueName src2_of(Instr* ins) {
    if (!ins->args || list_len(ins->args) < 2) return -1;
    return *(ValueName*)list_get(ins->args, 1);
}
static ValueName src3_of(Instr* ins) {
    if (!ins->args || list_len(ins->args) < 3) return -1;
    return *(ValueName*)list_get(ins->args, 2);
}

/* "block<id>" → <id>；无匹配返回 -1 */
static int parse_block_id(const char* lbl) {
    if (!lbl || strncmp(lbl, "block", 5) != 0) return -1;
    char *end;
    long id = strtol(lbl + 5, &end, 10);
    if (*end != '\0' || end == lbl + 5) return -1;
    return (int)id;
}

/* 块 id → Block*（block_map 查找） */
static Block* find_block_by_id(ISelContext* isel, int id) {
    if (!isel->block_map) return NULL;
    char key[32]; snprintf(key, sizeof(key), "%d", id);
    return (Block*)dict_get(isel->block_map, key);
}

/* 跳转目标标签名（无冒号）：L<id> */
static void block_label_name(char* out, size_t n, int id) {
    snprintf(out, n, "L%d", id);
}

/* ============================================================
 * Keil C251 ABI 参数寄存器（tinycc_c251 c251-lib.inc:169 实测验证）：
 *   u8:  {A(R11), R7, R6, R5, R4}  按序取第一个未被占用的字节寄存器
 *   u16: {WR6, WR4, WR2, WR0}      按序取第一个未被占用的 WR 对
 *   u32: {DR4, DR0}                (M2 报错，M3 支持)
 * 参数按声明序；u16 占用 R6:R7 影响后续 u8 槽（Keil 实测 three_args
 * u8,u16,u8 → A, WR6, R5：R7/R6 被 WR6 占）。
 * 返回: u8 → 字节寄存器号(0-15)；u16 → WR 索引(0/2/4/6)；-1 不足；-2 不支持的宽度
 * ============================================================ */
static int abi_param_reg(int *used, int sz, int *u8i, int *u16i) {
    if (sz <= 1) {
        static const int u8seq[5] = { 11, 7, 6, 5, 4 };  /* A, R7, R6, R5, R4 */
        while (*u8i < 5) {
            int r = u8seq[(*u8i)++];
            if (!used[r]) { used[r] = 1; return r; }
        }
        return -1;
    }
    if (sz <= 2) {
        static const int u16seq[4] = { 6, 4, 2, 0 };  /* WR6, WR4, WR2, WR0 */
        while (*u16i < 4) {
            int wr = u16seq[(*u16i)++];
            if (!used[wr] && !used[wr + 1]) { used[wr] = used[wr + 1] = 1; return wr; }
        }
        return -1;
    }
    return -2;  /* u32/指针: M3 */
}

/* 字节寄存器名（A=R11 用助记符 A） */
static const char* reg_name(int r) {
    if (r == 11) return "A";
    static char buf[8];
    snprintf(buf, sizeof(buf), "R%d", r);
    return buf;
}

/* 值宽度：1 字节 / 2 字（M2 只支持这两个；未知默认 2） */
static int value_size_of(ISelContext* isel, ValueName v) {
    C251GenContext *ctx = isel->ctx;
    if (v >= 0) {
        char *k = c251_key(v);
        Ctype *t = (Ctype*)dict_get(ctx->value_type, k);
        free(k);
        if (t) return t->size > 1 ? 2 : 1;
    }
    return 2;
}

/* 把值 v 的低字节装载到字节寄存器 r（Keil ABI u8 参数装载）：
 * 值在 WR → MOV Rr,低字节(R(wr+1))；常量 → MOV Rr,#v&0xFF；槽 → MOV Rr,__spill_N */
static void load_u8_to_r(ISelContext* isel, ValueName v, int r) {
    C251GenContext *ctx = isel->ctx;
    const char *rn = reg_name(r);
    int vr = isel_value_reg(ctx, v);
    if (vr >= 0) {
        char lo[16]; snprintf(lo, sizeof(lo), "R%d", vr + 1);  /* WRj 大端低字节 = R(j+1) */
        isel_emit(isel, "MOV", rn, lo);
        return;
    }
    char *k = c251_key(v);
    int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k);
    free(k);
    if (cv) {
        char imm[16]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFF);
        isel_emit(isel, "MOV", rn, imm);
        return;
    }
    char *sp = c251_value_spill(ctx, v);
    if (sp) {
        /* u8 值以 16 位形式存槽（大端：槽[0]=高字节=0, 槽[1]=低字节=u8）→
         * 16 位读槽后取低字节寄存器 R(t+1) */
        int t = isel_temp_wr(isel, -1, -1);
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), t);
        isel_emit(isel, "MOV", tbuf, sp);
        char lo[16]; snprintf(lo, sizeof(lo), "R%d", t + 1);
        isel_emit(isel, "MOV", rn, lo);
        return;
    }
    fprintf(stderr, "c251 isel: u8 实参 %d 无来源\n", v);
    isel_emit(isel, "MOV", rn, "#0");
}

/* 调用前活值压栈（caller-saves + 递归安全）：逆序 PUSH 活值 WR 对（WR6,WR4,WR2,WR0）
 * 字节序: WRj 大端 = Rj(高):R(j+1)(低)，PUSH 高字节在前（栈顶=低字节，POP 先取低） */
static void save_live_regs_stack(ISelContext* isel) {
    for (int i = 3; i >= 0; i--) {
        if (isel->reg_val[i] >= 0) {
            char rh[8], rl[8];
            snprintf(rh, sizeof(rh), "R%d", i * 2);
            snprintf(rl, sizeof(rl), "R%d", i * 2 + 1);
            isel_emit(isel, "PUSH", rh, NULL);
            isel_emit(isel, "PUSH", rl, NULL);
        }
    }
}

/* 调用后恢复：正序 POP（先低字节后高字节，逆压栈序） */
static void restore_live_regs_stack(ISelContext* isel) {
    for (int i = 0; i < 4; i++) {
        if (isel->reg_val[i] >= 0) {
            char rh[8], rl[8];
            snprintf(rh, sizeof(rh), "R%d", i * 2);
            snprintf(rl, sizeof(rl), "R%d", i * 2 + 1);
            isel_emit(isel, "POP", rl, NULL);
            isel_emit(isel, "POP", rh, NULL);
        }
    }
}

/* 调用前 spill 槽压栈（递归安全：spill 槽是静态 EDATA 地址，内层调用覆盖槽值后
 * 外层必须经 POP 恢复）。快照式：save 时记录 value_to_spill 当前全部槽并逆序压栈。
 * 中转固定用 WR6：WR6 若是活值已由 save_live_regs_stack 压栈（restore_live 最后
 * POP 恢复），故 save/restore 期间破坏 WR6 无害。不用 isel_temp_wr——其强制溢出
 * 路径会把 reg_val 置 -1，导致 restore_live_regs_stack 跳过 POP 造成栈不平衡。
 * 调用点内部临时槽（如 ret_spill 在 LCALL 后才分配）不在快照中，天然不受影响。 */
static List* save_spill_slots_stack(ISelContext* isel) {
    C251GenContext *ctx = isel->ctx;
    if (!ctx->value_to_spill) return NULL;
    List *slots = dict_values(ctx->value_to_spill);   /* char* 槽符号名（共享，不复制） */
    for (int i = list_len(slots) - 1; i >= 0; i--) {
        const char *sp = (const char*)list_get(slots, i);
        if (!sp || !sp[0]) continue;
        isel_emit(isel, "MOV", "WR6", sp);
        isel_emit(isel, "PUSH", "R6", NULL);
        isel_emit(isel, "PUSH", "R7", NULL);
    }
    return slots;
}

/* 调用后恢复：正序 POP（逆压栈序）回写快照中的槽。
 * 中转固定用 WR6（破坏 WR6 无害，restore_live 最后 POP 恢复活值）。
 * 注意：slots 的元素是 dict_values 借用的 char* 指针，不可 free 元素本身。 */
static void restore_spill_slots_stack(ISelContext* isel, List *slots) {
    if (!slots) return;
    for (int i = 0; i < list_len(slots); i++) {
        const char *sp = (const char*)list_get(slots, i);
        if (!sp || !sp[0]) continue;
        isel_emit(isel, "POP", "R7", NULL);
        isel_emit(isel, "POP", "R6", NULL);
        isel_emit(isel, "MOV", sp, "WR6");
    }
    /* 只释放 list 外壳，不清除 elem（借用的 dict 值） */
    free(slots);
}

/* 边缘 phi 拷贝：为跳转到 succ_id 的边发射 MOV __spill_phiN, param
 * （phi dest 在 isel_block 块首分配 EDATA 槽；参数按来源块选择）。
 * 两阶段并行拷贝语义：先读全部源到临时寄存器，再写目标槽——
 * 避免多 phi 时后写覆盖先读（gcd 循环 v8=phi[v3] 读到已更新的 v3 槽）。 */
static void emit_phi_copies(ISelContext* isel, int succ_id) {
    C251GenContext *ctx = isel->ctx;
    Block *succ = find_block_by_id(isel, succ_id);
    if (!succ || !succ->phis) return;
    char pred_label[32];
    snprintf(pred_label, sizeof(pred_label), "block%d", isel->current_block_id);

    /* 阶段 1：收集 (src, dest_slot) 对，并把源值快照到独立临时寄存器
     * （load_value_to_wr 处理源在寄存器/槽/常量三种情况；每个拷贝独立临时，互不干扰） */
    typedef struct PhiCopy { ValueName src; char *slot; } PhiCopy;
    PhiCopy copies[64];
    int ncopies = 0;
    int tmp_wr[64];  /* 每个拷贝的临时寄存器（-2 表示物化失败） */
    int prev_tmp = -1;
    for (Iter pit = list_iter(succ->phis); !iter_end(pit);) {
        Instr *phi = iter_next(&pit);
        if (!phi || phi->op != IROP_PHI || !phi->args || !phi->labels) continue;
        int idx = -1;
        for (int i = 0; i < (int)list_len(phi->labels); i++) {
            const char *l = (const char*)list_get(phi->labels, i);
            if (l && strcmp(l, pred_label) == 0) { idx = i; break; }
        }
        if (idx < 0 || idx >= (int)list_len(phi->args)) continue;
        ValueName src = *(ValueName*)list_get(phi->args, idx);
        char *sp = c251_value_spill(ctx, phi->dest);
        if (!sp) sp = c251_alloc_spill(ctx, phi->dest);
        if (ncopies >= 64) { fprintf(stderr, "c251 isel: phi 拷贝过多\n"); break; }
        copies[ncopies].src = src;
        copies[ncopies].slot = sp;
        /* isel_temp_wr 不标记占用，连续调用会返回同一 WR → 用 prev_tmp 回避 */
        int tmp = isel_temp_wr(isel, prev_tmp, -1);
        prev_tmp = tmp;
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
        if (load_value_to_wr(isel, src, tmp) == 0) {
            tmp_wr[ncopies] = tmp;
        } else {
            fprintf(stderr, "c251 isel: phi 参数无法物化 (v%d)\n", src);
            tmp_wr[ncopies] = -2;  /* 跳过 */
        }
        ncopies++;
    }
    /* 阶段 2：统一写目标槽（源值已快照在临时寄存器，槽覆盖不再互相干扰） */
    for (int i = 0; i < ncopies; i++) {
        if (tmp_wr[i] == -2) continue;
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp_wr[i]);
        isel_emit(isel, "MOV", copies[i].slot, tbuf);
    }
}


/* 生成内部标签名（无冒号）；发射时用 isel_emit_label */
static char* isel_new_label(ISelContext* isel, const char* prefix) {
    char buf[48];
    snprintf(buf, sizeof(buf), "%s%d", prefix, isel->label_counter++);
    return strdup(buf);
}

static void isel_emit_label(ISelContext* isel, const char* name) {
    if (!name) return;
    char *s = malloc(strlen(name) + 2);
    sprintf(s, "%s:", name);
    isel_emit(isel, s, NULL, NULL);
    free(s);
}

/* ins->labels 含 "imm" 标记 → 常量值在 ins->imm.ival（ssa_pass 约定） */
static bool has_imm_label(Instr* ins);

/* 值类型 unsigned 判断（def 时 value_type 已记录）；未知默认有符号（C 语义）
 * 注意：rank < int 的 uchar/ushort 会提升为 int（有符号），只有 size>=2 的原生
 * 无符号类型（uint）才按无符号比较（C 整数提升规则）。 */
static bool value_is_unsigned(ISelContext* isel, ValueName v) {
    C251GenContext *ctx = isel->ctx;
    if (v >= 0) {
        char *k = c251_key(v);
        Ctype *t = (Ctype*)dict_get(ctx->value_type, k);
        free(k);
        if (t && t->size >= 2) return get_attr(t->attr).ctype_unsigned;
    }
    return false;
}

/* 值宽度: 1=字节, 2=字（未知默认 2；LOAD 目标/比较等用）。
 * 注：334 行已有 value_size_of(ISelContext*,...)，本版本为 C251GenContext* 签名，
 * 仅 LOAD/STORE 用（此处入参是 ctx）。 */
static int value_size_of_ctx(C251GenContext *ctx, ValueName v) {
    if (v >= 0) {
        char *k = c251_key(v);
        Ctype *t = (Ctype*)dict_get(ctx->value_type, k);
        free(k);
        if (t) {
            int sz = t->size;
            return sz <= 1 ? 1 : (sz > 2 ? sz : 2);  /* 保留 long (4) 尺寸 */
        }
    }
    return 2;
}

/* 按声明判定无符号（char 加载扩展用；与比较的提升规则不同——
 * unsigned char 加载必须零扩展为 0-255，signed char 符号扩展） */
static bool value_decl_unsigned(C251GenContext *ctx, ValueName v) {
    if (v >= 0) {
        char *k = c251_key(v);
        Ctype *t = (Ctype*)dict_get(ctx->value_type, k);
        free(k);
        if (t) return get_attr(t->attr).ctype_unsigned;
    }
    return false;
}

/* 全局符号字节数（sym_size dict；未知默认 2——spill 槽即 2B） */
static int sym_size_of(C251GenContext *ctx, const char *sym) {
    if (sym && ctx->sym_size) {
        int *s = (int*)dict_get(ctx->sym_size, (char*)sym);
        if (s) return *s <= 1 ? 1 : 2;
    }
    return 2;
}

/* CMP lhs,rhs：lhs 必须物化在寄存器（比较方向不可交换）；rhs 可为寄存器/常量/槽/imm-label */
static void emit_cmp(ISelContext* isel, Instr* ins, ValueName s1, ValueName s2, int avoid_wr) {
    C251GenContext *ctx = isel->ctx;
    int r1 = isel_value_reg(ctx, s1);
    if (r1 < 0) {
        int t = isel_temp_wr(isel, avoid_wr, -1);
        if (load_value_to_wr(isel, s1, t) < 0) {
            fprintf(stderr, "c251 isel: CMP lhs 无法物化 (v%d)\n", s1);
            return;
        }
        r1 = t;
    }
    char r1buf[16]; wr_name(r1buf, sizeof(r1buf), r1);
    int r2 = isel_value_reg(ctx, s2);
    if (r2 >= 0) {
        char r2buf[16]; wr_name(r2buf, sizeof(r2buf), r2);
        isel_emit(isel, "CMP", r1buf, r2buf);
        return;
    }
    if (s2 >= 0) {
        char *k = c251_key(s2);
        int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k);
        free(k);
        if (cv) {
            char imm[32]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFFFF);
            isel_emit(isel, "CMP", r1buf, imm);
            return;
        }
        char *sp = c251_value_spill(ctx, s2);
        if (sp) {
            int t2 = isel_temp_wr(isel, r1, avoid_wr);
            char t2buf[16]; wr_name(t2buf, sizeof(t2buf), t2);
            isel_emit(isel, "MOV", t2buf, sp);
            isel_emit(isel, "CMP", r1buf, t2buf);
            return;
        }
    }
    /* ssa_pass pass_binop_const_inline 约定：常量 def 被内联删除后值在 ins->imm.ival */
    if (has_imm_label(ins)) {
        char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
        isel_emit(isel, "CMP", r1buf, imm);
        return;
    }
    fprintf(stderr, "c251 isel: CMP rhs 无来源 (v%d)\n", s2);
    isel_emit(isel, "CMP", r1buf, "#0");
}

/* 比较结果物化为 0/1（M2 简化）：CMP; MOV dest,#0; Bcc L1; MOV dest,#1; L1:
 * jcc = "结果为 0" 时跳走的条件（即比较成立的否定条件） */
static void emit_compare_result(ISelContext* isel, Instr* ins, const char* jcc) {
    C251GenContext *ctx = isel->ctx;
    ValueName s1 = src1_of(ins), s2 = src2_of(ins);
    int wr = isel_alloc_wr(isel, ins->dest);
    emit_cmp(isel, ins, s1, s2, wr);
    char *lbl = isel_new_label(isel, "?C");
    if (wr >= 0) {
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
        isel_emit(isel, "MOV", wbuf, "#0");
        isel_emit(isel, jcc, lbl, NULL);
        isel_emit(isel, "MOV", wbuf, "#1");
    } else {
        int tmp = isel_temp_wr(isel, -1, -1);
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
        isel_emit(isel, "MOV", tbuf, "#0");
        isel_emit(isel, jcc, lbl, NULL);
        isel_emit(isel, "MOV", tbuf, "#1");
        char *sp = c251_alloc_spill(ctx, ins->dest);
        isel_emit(isel, "MOV", sp, tbuf);
    }
    isel_emit_label(isel, lbl);
    free(lbl);
}

/* BR 免物化：条件跳转反转。jcc 为 emit_compare_result 的"结果为 0 跳走"条件，
 * 返回"结果为 1（真）跳转"的条件（BR 直接用）。无反转则返回 NULL。 */
static const char* invert_jcc_str(const char* jcc) {
    if (!jcc) return NULL;
    if (!strcmp(jcc, "JE"))   return "JNE";
    if (!strcmp(jcc, "JNE"))  return "JE";
    if (!strcmp(jcc, "JG"))   return "JLE";
    if (!strcmp(jcc, "JLE"))  return "JG";
    if (!strcmp(jcc, "JSL"))  return "JSGE";
    if (!strcmp(jcc, "JSGE")) return "JSL";
    if (!strcmp(jcc, "JSLE")) return "JSG";
    if (!strcmp(jcc, "JSG"))  return "JSLE";
    if (!strcmp(jcc, "JC"))   return "JNC";
    if (!strcmp(jcc, "JNC"))  return "JC";
    if (!strcmp(jcc, "JZ"))   return "JNZ";
    if (!strcmp(jcc, "JNZ"))  return "JZ";
    return NULL;
}

/* 指令 args 是否使用值 v */
static bool instr_uses_value(Instr* ins, ValueName v) {
    if (!ins || !ins->args) return false;
    for (Iter it = list_iter(ins->args); !iter_end(it);) {
        ValueName *ap = iter_next(&it);
        if (ap && *ap == v) return true;
    }
    return false;
}

/* block_instrs[from..n) 中 v 被使用的次数（含 BR 自身） */
static int count_block_uses_from(ISelContext* isel, int from, ValueName v) {
    if (v < 0) return 0;
    int cnt = 0;
    for (int i = from; i < isel->block_instr_count; i++) {
        Instr *ins = isel->block_instrs[i];
        if (!ins || !ins->args) continue;
        for (Iter it = list_iter(ins->args); !iter_end(it);) {
            ValueName *ap = iter_next(&it);
            if (ap && *ap == v) cnt++;
        }
    }
    return cnt;
}

/* 从 pos+1 起找下一条有效指令（跳过 NOP 和 CONST——CONST 的 MOV 不影响标志） */
static Instr* next_non_nop(ISelContext* isel, int pos) {
    for (int i = pos + 1; i < isel->block_instr_count; i++) {
        Instr *ins = isel->block_instrs[i];
        if (!ins) continue;
        if (ins->op == IROP_NOP || ins->op == IROP_CONST) continue;
        return ins;
    }
    return NULL;
}

/* 在 block_instrs 中查找值 v 的常量 def（CONST 指令）；找到且为 0 返回 true。
 * 不能依赖 value_to_const——const def 可能在当前指令之后才被 isel 处理。 */
static bool block_const_is_zero(ISelContext* isel, ValueName v) {
    if (v < 0) return false;
    for (int i = 0; i < isel->block_instr_count; i++) {
        Instr *ins = isel->block_instrs[i];
        if (ins && ins->op == IROP_CONST && ins->dest == v)
            return ins->imm.ival == 0;
    }
    return false;
}

/* 比较指令（EQ/NE/LT/GT/LE/GE）免物化前瞻：
 * 若 dest 仅被后续 BR（或 NE dest,0 → BR）使用，则只发 CMP 并记录 hint，
 * BR 直接复用比较标志。命中返回 true，调用方跳过物化。
 * 支持两种模式：
 *   A) cmp_dest → BR(dest)          （BR 直接用比较结果）
 *   B) cmp_dest → NE(dest,0) → BR   （布尔化比较结果再跳）
 */
static bool try_br_fold(ISelContext* isel, Instr* ins, const char* jcc) {
    ValueName dest = ins->dest;
    if (dest < 0) return false;
    if (is_global_live(isel->global_live, dest)) return false;  /* 跨块活：必须物化 */
    if (isel->block_instr_pos + 1 >= isel->block_instr_count) return false;

    ValueName s1 = src1_of(ins), s2 = src2_of(ins);
    int use_count = count_block_uses_from(isel, isel->block_instr_pos + 1, dest);
    if (use_count == 0) return false;   /* 无人用：不该发生（SSA 正常有 BR 用） */

    Instr *nxt = next_non_nop(isel, isel->block_instr_pos);
    if (!nxt) return false;
    /* nxt 在数组中的位置（跳过 NOP/CONST 后） */
    int nxt_idx = isel->block_instr_pos + 1;
    while (nxt_idx < isel->block_instr_count) {
        Instr *c = isel->block_instrs[nxt_idx];
        if (c && c->op != IROP_NOP && c->op != IROP_CONST) break;
        nxt_idx++;
    }

    /* 模式 A：直接 BR(dest) */
    if (nxt->op == IROP_BR && instr_uses_value(nxt, dest) && use_count == 1) {
        emit_cmp(isel, ins, s1, s2, -1);
        isel->br_hint_cond = dest;
        snprintf(isel->br_hint_jump, sizeof(isel->br_hint_jump), "%s",
                 invert_jcc_str(jcc) ? invert_jcc_str(jcc) : "JNE");
        isel->br_hint_ne_skip = -1;
        return true;
    }

    /* 模式 B：NE(dest,0) → BR(ne_dest) */
    if (nxt->op == IROP_NE && instr_uses_value(nxt, dest)) {
        Instr *nn = next_non_nop(isel, nxt_idx);
        if (nn && nn->op == IROP_BR && instr_uses_value(nn, nxt->dest)
            && count_block_uses_from(isel, isel->block_instr_pos + 1, dest) == 1
            && count_block_uses_from(isel, nxt_idx + 1, nxt->dest) == 1) {
            /* NE 必须是 (dest, 0)：检查 NE 另一操作数为常量 0（扫描块内 CONST def） */
            ValueName na = src1_of(nxt), nb = src2_of(nxt);
            bool is_zero = false;
            if (na == dest)      is_zero = block_const_is_zero(isel, nb);
            else if (nb == dest) is_zero = block_const_is_zero(isel, na);
            if (is_zero) {
                emit_cmp(isel, ins, s1, s2, -1);
                isel->br_hint_cond = dest;
                snprintf(isel->br_hint_jump, sizeof(isel->br_hint_jump), "%s",
                         invert_jcc_str(jcc) ? invert_jcc_str(jcc) : "JNE");
                isel->br_hint_ne_skip = nxt->dest;
                return true;
            }
        }
    }
    return false;
}

/* ins->labels 含 "imm" 标记 → 常量值在 ins->imm.ival（ssa_pass 约定） */
static bool has_imm_label(Instr* ins) {
    if (!ins || !ins->labels) return false;
    for (Iter it = list_iter(ins->labels); !iter_end(it);) {
        const char *l = iter_next(&it);
        if (l && strcmp(l, "imm") == 0) return true;
    }
    return false;
}

/* 编码器 imm 支持：ADD/SUB 有 WRj,#imm16（2E/9E）；MUL 只支持 WRj,WRk（AD）。
 * MUL 遇 imm 必须物化到寄存器，否则发射不可编码指令（编码器返回 -1、无字节产生）。 */
static bool op_supports_imm(int op) {
    return op == IROP_ADD || op == IROP_SUB || op == IROP_AND || op == IROP_OR || op == IROP_XOR;
}

/* 用立即数发射 op：支持 imm 的 op 直接 op WRj,#imm；否则物化 imm 到临时寄存器再 op */
static void emit_op_with_imm(ISelContext* isel, const char* opm, int op,
                             const char* wbuf, int wr, int r1, long long val) {
    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", val & 0xFFFF);
    if (op_supports_imm(op)) {
        isel_emit(isel, opm, wbuf, imm);
    } else {
        int tmp = isel_temp_wr(isel, wr, r1);
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
        isel_emit(isel, "MOV", tbuf, imm);
        isel_emit(isel, opm, wbuf, tbuf);
    }
}

/* 发射 "opm wbuf(已含 s1), src2"：src2 可为 寄存器/常量/溢出槽/imm-label */
static void emit_binop_src2(ISelContext* isel, const char* opm, int op,
                            const char* wbuf, int w, ValueName s1, ValueName s2,
                            bool imm_label, long long imm_val) {
    C251GenContext *ctx = isel->ctx;
    int r2 = isel_value_reg(ctx, s2);
    if (r2 >= 0) {
        char r2buf[16]; wr_name(r2buf, sizeof(r2buf), r2);
        isel_emit(isel, opm, wbuf, r2buf);
        return;
    }
    int64_t *cv = NULL;
    if (s2 >= 0) {
        char *k = c251_key(s2);
        cv = (int64_t*)dict_get(ctx->value_to_const, k);
        free(k);
    }
    if (cv) { emit_op_with_imm(isel, opm, op, wbuf, w, isel_value_reg(ctx, s1), *cv); return; }
    if (s2 >= 0) {
        char *sp = c251_value_spill(ctx, s2);
        if (sp) {
            int t2 = isel_temp_wr(isel, w, isel_value_reg(ctx, s1));
            char t2buf[16]; wr_name(t2buf, sizeof(t2buf), t2);
            isel_emit(isel, "MOV", t2buf, sp);
            isel_emit(isel, opm, wbuf, t2buf);
            return;
        }
        fprintf(stderr, "c251 isel: op 的 s2 无寄存器/常量/槽 (v%d)\n", s2);
        isel_emit(isel, "MOV", wbuf, "#0");
        return;
    }
    if (imm_label) { emit_op_with_imm(isel, opm, op, wbuf, w, isel_value_reg(ctx, s1), imm_val); return; }
    /* 单操作数兜底 */
    isel_emit(isel, "MOV", wbuf, "#0");
}

void isel_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins) return;
    C251GenContext *ctx = isel->ctx;

    /* 记录值类型（供比较有符号判断等；def 先于 use，SSA 顺序保证） */
    if (ins->dest >= 0 && ins->type) {
        dict_put(ctx->value_type, c251_key(ins->dest), ins->type);
    }

    switch (ins->op) {
    case IROP_NOP:
        break;
    case IROP_CONST: {
        /* 记录常量值（供 imm 折叠；任何分配路径都记录） */
        int64_t *cv = malloc(sizeof(int64_t)); *cv = ins->imm.ival;
        dict_put(ctx->value_to_const, c251_key(ins->dest), cv);

        int wr = isel_alloc_wr(isel, ins->dest);
        char imm[32];
        int is_byte = ins->type && ins->type->size <= 1;
        snprintf(imm, sizeof(imm), "#%lld",
                 is_byte ? (ins->imm.ival & 0xFF) : (ins->imm.ival & 0xFFFF));
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            isel_emit(isel, "MOV", wbuf, imm);
        } else {
            /* dest 溢出：临时寄存器存槽（编码器无 MOV dir16,#imm） */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            isel_emit(isel, "MOV", tbuf, imm);
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_PARAM: {
        /* 被调函数参数：按声明序从 ABI 寄存器装载（Keil C251，查预计算表） */
        int idx = isel->param_counter++;
        if (idx >= isel->param_abi_count) {
            fprintf(stderr, "c251 isel: 参数 %d 超出预计算表\n", idx);
            break;
        }
        int sz = isel->param_abi_sz[idx];
        int reg = isel->param_abi_reg[idx];
        if (reg == -2) { fprintf(stderr, "c251 isel: 参数 %d 宽度>16位 M3 支持\n", idx); break; }
        if (reg < 0) { fprintf(stderr, "c251 isel: 参数 %d 寄存器不足 (M3 栈传参)\n", idx); break; }
        /* 其他参数的 ABI 字节槽（物化目标必须避开，防覆写未消费参数） */
        int avoid[32]; int navoid = 0;
        for (int j = 0; j < isel->param_abi_nbytes; j++) {
            int b = isel->param_abi_bytes[j];
            int mine = (sz <= 1) ? (b == reg) : (b == reg || b == reg + 1);
            if (!mine) avoid[navoid++] = b;
        }
        if (sz <= 1) {
            /* u8 参数在字节寄存器 → MOVZ WRj,Rr（零扩展物化；目标避开其他 ABI 槽） */
            int wr = isel_alloc_wr_avoid(isel, ins->dest, avoid, navoid);
            if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                isel_emit(isel, "MOVZ", wbuf, reg_name(reg));
            } else {
                int tmp = isel_temp_wr_avoid_bytes(isel, -1, -1, avoid, navoid);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                isel_emit(isel, "MOVZ", tbuf, reg_name(reg));
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
        } else {
            /* u16 参数已在 WRreg：优先直接绑定 ABI 槽为值寄存器（零 MOV，天然不冲突）；
             * 槽被占用则物化到避开其他 ABI 槽的寄存器 */
            char *key = c251_key(ins->dest);
            int *exist = (int*)dict_get(ctx->value_to_reg, key);
            if (!exist && isel->reg_val[reg/2] < 0) {
                int *slot = malloc(sizeof(int)); *slot = reg;
                dict_put(ctx->value_to_reg, key, slot);
                isel->reg_val[reg/2] = ins->dest;
            } else {
                free(key);
                int wr = isel_alloc_wr_avoid(isel, ins->dest, avoid, navoid);
                if (wr >= 0) {
                    char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                    char rbuf[16]; wr_name(rbuf, sizeof(rbuf), reg);
                    isel_emit(isel, "MOV", wbuf, rbuf);
                } else {
                    int tmp = isel_temp_wr_avoid_bytes(isel, -1, -1, avoid, navoid);
                    char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                    if (tmp != reg) {
                        char rbuf[16]; wr_name(rbuf, sizeof(rbuf), reg);
                        isel_emit(isel, "MOV", tbuf, rbuf);
                    }
                    char *sp = c251_alloc_spill(ctx, ins->dest);
                    isel_emit(isel, "MOV", sp, tbuf);
                }
            }
        }
        break;
    }
    case IROP_ADD:
    case IROP_SUB:
    case IROP_MUL: {
        const char *opm = (ins->op == IROP_ADD) ? "ADD" : (ins->op == IROP_SUB) ? "SUB" : "MUL";
        ValueName s1 = src1_of(ins), s2 = src2_of(ins);
        bool il = has_imm_label(ins);
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s1, wr);
            emit_binop_src2(isel, opm, ins->op, wbuf, wr, s1, s2, il, ins->imm.ival);
        } else {
            /* dest 溢出：计算到临时 → 存槽 */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            load_value_to_wr(isel, s1, tmp);
            emit_binop_src2(isel, opm, ins->op, tbuf, tmp, s1, s2, il, ins->imm.ival);
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_AND:
    case IROP_OR:
    case IROP_XOR: {
        /* ANL/ORL/XRL WRj,WRk 或 #imm16 (5D/4D/6D 与 5E/4E/6E 形态)
         * 复用 ADD 模式：dest 物化 s1 + emit_binop_src2（寄存器/常量/槽/imm-label） */
        const char *opm = (ins->op == IROP_AND) ? "ANL" : (ins->op == IROP_OR) ? "ORL" : "XRL";
        ValueName s1 = src1_of(ins), s2 = src2_of(ins);
        bool il = has_imm_label(ins);
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s1, wr);
            emit_binop_src2(isel, opm, ins->op, wbuf, wr, s1, s2, il, ins->imm.ival);
        } else {
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            load_value_to_wr(isel, s1, tmp);
            emit_binop_src2(isel, opm, ins->op, tbuf, tmp, s1, s2, il, ins->imm.ival);
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_NOT: {
        /* ~x: XRL WRj,#FFFF（16 位取反；低 8 位结果对 8 位值同样正确） */
        ValueName s1 = src1_of(ins);
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s1, wr);
            isel_emit(isel, "XRL", wbuf, "#FFFF");
        } else {
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            load_value_to_wr(isel, s1, tmp);
            isel_emit(isel, "XRL", tbuf, "#FFFF");
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_NEG: {
        /* -x: XRL WRj,#FFFF + INC WRj（补码；251 无 NEG 指令） */
        ValueName s1 = src1_of(ins);
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s1, wr);
            isel_emit(isel, "XRL", wbuf, "#FFFF");
            isel_emit(isel, "INC", wbuf, NULL);
        } else {
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            load_value_to_wr(isel, s1, tmp);
            isel_emit(isel, "XRL", tbuf, "#FFFF");
            isel_emit(isel, "INC", tbuf, NULL);
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_LNOT: {
        /* !x: x==0 → 1, 否则 0。CMP x,#0; 物化 */
        ValueName s1 = src1_of(ins);
        int wr = isel_alloc_wr(isel, ins->dest);
        char *l1 = isel_new_label(isel, "?L");
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s1, wr);
            isel_emit(isel, "CMP", wbuf, "#0");
            isel_emit(isel, "MOV", wbuf, "#0");   /* MOV 不破坏标志 */
            isel_emit(isel, "JNE", l1, NULL);
            isel_emit(isel, "MOV", wbuf, "#1");
        } else {
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            load_value_to_wr(isel, s1, tmp);
            isel_emit(isel, "CMP", tbuf, "#0");
            isel_emit(isel, "MOV", tbuf, "#0");
            isel_emit(isel, "JNE", l1, NULL);
            isel_emit(isel, "MOV", tbuf, "#1");
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        isel_emit_label(isel, l1);
        free(l1);
        break;
    }
    case IROP_SHL:
    case IROP_SHR: {
        /* 移位：251 SLL/SRL/SRA 为移位 1 位指令（regop2_shift, 第二字段忽略）。
         * M2：常量移位量展开 N 次；有符号右移用 SRA；变量移位量 M2.5。 */
        ValueName s1 = src1_of(ins), s2 = src2_of(ins);
        long long amt = 0; bool have_amt = false;
        if (has_imm_label(ins)) { amt = ins->imm.ival; have_amt = true; }
        else if (s2 >= 0) {
            char *k = c251_key(s2);
            int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k);
            free(k);
            if (cv) { amt = *cv; have_amt = true; }
        }
        bool is_shr = ins->op == IROP_SHR;
        bool is_signed_shr = is_shr && !value_is_unsigned(isel, s1);
        int wr = isel_alloc_wr(isel, ins->dest);
        int w = wr >= 0 ? wr : isel_temp_wr(isel, -1, -1);
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), w);
        load_value_to_wr(isel, s1, w);
        if (!have_amt) {
            fprintf(stderr, "c251 isel: 变量移位量 M2.5 支持 (v%d)，发射 0 兜底\n", ins->dest);
            isel_emit(isel, "MOV", wbuf, "#0");
        } else {
            long long n = amt & 0xFFFF;
            if (n == 0) {
                /* 移位量 0：无操作（值已在 dest） */
            } else if (is_signed_shr && n >= 15) {
                /* SRA 饱和：16 位值算术右移 ≥15 次后符号扩展稳定 */
                for (int i = 0; i < 15; i++) isel_emit(isel, "SRA", wbuf, NULL);
            } else if (n >= 16) {
                /* 16 位逻辑左移/右移 ≥16 位 → 0 */
                isel_emit(isel, "MOV", wbuf, "#0");
            } else {
                const char *opm = is_shr ? (is_signed_shr ? "SRA" : "SRL") : "SLL";
                for (long long i = 0; i < n; i++) isel_emit(isel, opm, wbuf, NULL);
            }
        }
        if (wr < 0) {
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, wbuf);
        }
        break;
    }
    case IROP_DIV:
    case IROP_MOD: {
        /* 16 位：硬件 DIV WRj,WRk (8D)——商→目标 WRj, 余数→DR 对另一侧。
         * 无符号：直接 DIV。有符号（C99 截断向零）：符号算法。
         * 32 位：需运行时库（M3），先报错 + 0 兜底。 */
        ValueName s1 = src1_of(ins), s2 = src2_of(ins);
        bool want_mod = ins->op == IROP_MOD;
        /* C 常用算术转换：任一操作数无符号即按无符号除法（与同文件比较路径 || 用法一致） */
        bool us = value_is_unsigned(isel, s1) || value_is_unsigned(isel, s2);
        int size = ins->type ? ins->type->size : 2;
        if (size > 2) {
            fprintf(stderr, "c251 isel: 32 位 DIV/MOD 需运行时库 (M3)\n");
            int wr = isel_alloc_wr(isel, ins->dest);
            if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                isel_emit(isel, "MOV", wbuf, "#0");
            } else {
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, "#0");
            }
            break;
        }
        if (us) {
            /* 无符号：直接 DIV t1,t2 → q=t1, r=partner(t1) */
            int t1 = isel_temp_wr(isel, -1, -1);
            int t2 = isel_temp_wr(isel, t1, -1);
            char b1[16], b2[16]; wr_name(b1, sizeof(b1), t1); wr_name(b2, sizeof(b2), t2);
            load_value_to_wr(isel, s1, t1);
            if (has_imm_label(ins)) {
                char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
                isel_emit(isel, "MOV", b2, imm);
            } else {
                load_value_to_wr(isel, s2, t2);
            }
            isel_emit(isel, "DIV", b1, b2);
            int pr = (t1 & 2) == 0 ? t1 + 2 : t1 - 2;  /* 余数所在 DR 对另一侧 */
            char pbuf[16]; wr_name(pbuf, sizeof(pbuf), pr);
            int dw = isel_alloc_wr(isel, ins->dest);
            if (want_mod) {
                if (dw >= 0 && dw != pr) { char db[16]; wr_name(db, sizeof(db), dw); isel_emit(isel, "MOV", db, pbuf); }
                else if (dw < 0) { char *sp = c251_alloc_spill(ctx, ins->dest); isel_emit(isel, "MOV", sp, pbuf); }
                /* dw == pr：余数已在 dest */
            } else {
                if (dw >= 0 && dw != t1) { char db[16]; wr_name(db, sizeof(db), dw); isel_emit(isel, "MOV", db, b1); }
                else if (dw < 0) { char *sp = c251_alloc_spill(ctx, ins->dest); isel_emit(isel, "MOV", sp, b1); }
                /* dw == t1：商已在 dest */
            }
        } else {
            /* 有符号除法（截断向零）：
             *   f1 = (num<0), f2 = (den<0)；anum=|num|, aden=|den|
             *   DIV → q, r；q 符号 = f1^f2；r 符号 = f1
             * R0/R1 作标志 → 占 WR0，temp 全部避开 WR0 */
            int avoid0[1] = { 0 };
            int t1s = isel_temp_wr_avoid_bytes(isel, -1, -1, avoid0, 1);
            int t2s = isel_temp_wr_avoid_bytes(isel, t1s, -1, avoid0, 1);
            char sb1[16], sb2[16];
            wr_name(sb1, sizeof(sb1), t1s); wr_name(sb2, sizeof(sb2), t2s);
            load_value_to_wr(isel, s1, t1s);
            if (has_imm_label(ins)) {
                char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
                isel_emit(isel, "MOV", sb2, imm);
            } else {
                load_value_to_wr(isel, s2, t2s);
            }
            char *l1 = isel_new_label(isel, "?D"), *l2 = isel_new_label(isel, "?D");
            char *l3 = isel_new_label(isel, "?D"), *l4 = isel_new_label(isel, "?D");
            /* f1 = num<0（有符号判断: CMP 后 JSGE 有符号>=0 跳过取负） */
            isel_emit(isel, "MOV", "R0", "#0");
            isel_emit(isel, "CMP", sb1, "#0");
            isel_emit(isel, "JSGE", l1, NULL);
            isel_emit(isel, "XRL", sb1, "#FFFF");
            isel_emit(isel, "INC", sb1, NULL);
            isel_emit(isel, "MOV", "R0", "#1");
            isel_emit_label(isel, l1);
            /* f2 = den<0 */
            isel_emit(isel, "MOV", "R1", "#0");
            isel_emit(isel, "CMP", sb2, "#0");
            isel_emit(isel, "JSGE", l2, NULL);
            isel_emit(isel, "XRL", sb2, "#FFFF");
            isel_emit(isel, "INC", sb2, NULL);
            isel_emit(isel, "MOV", "R1", "#1");
            isel_emit_label(isel, l2);
            /* 无符号除 */
            isel_emit(isel, "DIV", sb1, sb2);   /* q→t1s, r→prs */
            int prs = (t1s & 2) == 0 ? t1s + 2 : t1s - 2;
            char spb[16]; wr_name(spb, sizeof(spb), prs);
            int dw = isel_alloc_wr(isel, ins->dest);
            int avoid3[2] = { dw >= 0 ? dw : -1, 0 };
            int t3 = isel_temp_wr_avoid_bytes(isel, t1s, prs, avoid3, dw >= 0 ? 2 : 1);
            char b3[16]; wr_name(b3, sizeof(b3), t3);
            isel_emit(isel, "MOV", b3, spb);    /* t3 = r */
            /* q 符号: f1^f2 */
            isel_emit(isel, "MOV", "A", "R0");
            isel_emit(isel, "XRL", "A", "R1");
            isel_emit(isel, "JZ", l3, NULL);
            isel_emit(isel, "XRL", sb1, "#FFFF");
            isel_emit(isel, "INC", sb1, NULL);
            isel_emit_label(isel, l3);
            /* r 符号: f1（余数符号同被除数） */
            if (want_mod) {
                isel_emit(isel, "MOV", "A", "R0");
                isel_emit(isel, "JZ", l4, NULL);
                isel_emit(isel, "XRL", b3, "#FFFF");
                isel_emit(isel, "INC", b3, NULL);
                isel_emit_label(isel, l4);
            }
            /* 结果 → dest */
            if (want_mod) {
                if (dw >= 0 && dw != t3) { char db[16]; wr_name(db, sizeof(db), dw); isel_emit(isel, "MOV", db, b3); }
                else if (dw < 0) { char *sp = c251_alloc_spill(ctx, ins->dest); isel_emit(isel, "MOV", sp, b3); }
                /* dw == t3：余数已在 dest */
            } else {
                if (dw >= 0 && dw != t1s) { char db[16]; wr_name(db, sizeof(db), dw); isel_emit(isel, "MOV", db, sb1); }
                else if (dw < 0) { char *sp = c251_alloc_spill(ctx, ins->dest); isel_emit(isel, "MOV", sp, sb1); }
                /* dw == t1s：商已在 dest */
            }
            free(l1); free(l2); free(l3); free(l4);
        }
        break;
    }
    case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE: {
        /* M2 简化：比较结果物化为 0/1 值；BR 紧邻时免物化（try_br_fold） */
        bool us = value_is_unsigned(isel, src1_of(ins)) || value_is_unsigned(isel, src2_of(ins));
        const char *jcc;
        switch (ins->op) {
        case IROP_EQ: jcc = "JNE"; break;               /* 相等→1；不等跳走置 0 */
        case IROP_NE: jcc = "JE";  break;               /* 不等→1；相等跳走置 0 */
        case IROP_LT: jcc = us ? "JNC" : "JSGE"; break;/* 无符号 a<b→cy=1; 有符号 a<b→N≠OV */
        case IROP_GT: jcc = us ? "JLE" : "JSLE"; break;
        case IROP_LE: jcc = us ? "JG"  : "JSG";  break;
        case IROP_GE: jcc = us ? "JC"  : "JSL";  break;
        default: jcc = "JNE"; break;
        }
        /* 本指令是模式 B 中被前一条比较指令消费的 NE？→ 跳过（hint 已记录，
         * br_hint_ne_skip 保留给 BR 匹配用，BR 命中后统一清除） */
        if (ins->op == IROP_NE && isel->br_hint_ne_skip == ins->dest) {
            break;
        }
        if (!try_br_fold(isel, ins, jcc)) {
            emit_compare_result(isel, ins, jcc);
        }
        break;
    }
    case IROP_RET: {
        ValueName v = src1_of(ins);
        /* 返回宽度: u8 → A(R11)；u16 → WR6（Keil C251 实测, golden tmp_func3.src） */
        bool is_u8 = ins->type && ins->type->size <= 1;
        if (is_u8) {
            if (v >= 0) {
                load_u8_to_r(isel, v, 11);  /* 值低字节 → A */
            } else if (has_imm_label(ins)) {
                char imm[16]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFF);
                isel_emit(isel, "MOV", "A", imm);
            }
        } else {
            if (v >= 0) {
                int r = isel_value_reg(ctx, v);
                if (r >= 0) {
                    if (r != 6) { char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r); isel_emit(isel, "MOV", "WR6", rbuf); }
                } else {
                    load_value_to_wr(isel, v, 6);   /* const → MOV WR6,#imm; spill → MOV WR6,__spill_N */
                }
            } else if (has_imm_label(ins)) {
                /* ret const → 常量直接进 WR6 */
                char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
                isel_emit(isel, "MOV", "WR6", imm);
            }
        }
        /* 中断函数 → RETI (恢复中断); 普通函数 → RET。中断 epilog: POP 逆序恢复 R0-R7 + PSW */
        if (ctx->current_func && ctx->current_func->is_interrupt) {
            for (int rr = 7; rr >= 0; rr--) {
                char rnm[8]; snprintf(rnm, sizeof(rnm), "R%d", rr);
                isel_emit(isel, "POP", rnm, NULL);
            }
            isel_emit(isel, "POP", "0xD0", NULL);
            isel_emit(isel, "RETI", NULL, NULL);
        } else {
            isel_emit(isel, "RET", NULL, NULL);
        }
        break;
    }
    case IROP_CALL: {
        /* 函数调用（Keil C251 ABI）: labels[0]=函数名, args=实参值, dest=返回值
         * 1) 活值全部溢出（caller-saves 保守版，参数装载会覆盖 ABI 寄存器）
         * 2) 逆序装载实参到 ABI 寄存器（防先装载的实参被后装载覆盖）
         * 3) LCALL
         * 4) 返回值物化 (u8→A, u16→WR6) */
        const char *fname = (ins->labels && list_len(ins->labels) > 0)
            ? (const char*)list_get(ins->labels, 0) : NULL;
        /* 间接调用: call *ptr @<indirect>() → labels 中含 "indirect" */
        int is_indirect = 0;
        if (ins->labels) {
            for (int i = 0; i < (int)list_len(ins->labels); i++) {
                const char *l = (const char*)list_get(ins->labels, i);
                if (l && strcmp(l, "indirect") == 0) { is_indirect = 1; break; }
            }
        }
        if (!fname || is_indirect) {
            /* 间接调用: call *ptr @indirect() → LCALL @WRj (0089-fptr) */
            ValueName fptr = ins->args && list_len(ins->args) > 0
                ? *(ValueName*)list_get(ins->args, 0) : 0;
            if (fptr > 0) {
                int wr = isel_temp_wr(isel, -1, -1);
                if (load_value_to_wr(isel, fptr, wr) == 0) {
                    char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                    char ind[32]; snprintf(ind, sizeof(ind), "@%s", wbuf);
                    isel_emit(isel, "LCALL", ind, NULL);
                } else {
                    fprintf(stderr, "c251 isel: 间接调用 指针值无法装载 (v%d)\n", fptr);
                }
            } else {
                fprintf(stderr, "c251 isel: 间接调用 M2.5 支持\n");
            }
            /* 返回值: u16 → WR6 */
            if (ins->dest > 0) {
                int dw = isel_alloc_wr(isel, ins->dest);
                if (dw >= 0 && dw != 6) {
                    char db[16]; wr_name(db, sizeof(db), dw);
                    isel_emit(isel, "MOV", db, "WR6");
                }
                /* dw==6: 返回值已在 WR6 */
            }
            break;
        }
        int nargs = ins->args ? (int)list_len(ins->args) : 0;
        /* ② 实参 → ABI 寄存器：先按声明序预计算（与被调方 PARAM 消费序一致）；
         *    源值寄存器命中其他实参的 ABI 目标时预转存（防逆序装载互相覆盖）；
         *    再逆序装载 */
        int used[16] = { 0 };
        int u8i = 0, u16i = 0;
        int fail = 0;
        int abi_regs[32], abi_sz[32], abi_sz8[32];
        int nabi = 0;
        for (int i = 0; i < nargs && !fail; i++) {
            ValueName av = *(ValueName*)list_get(ins->args, i);
            int asz = value_size_of(isel, av);
            int reg = abi_param_reg(used, asz, &u8i, &u16i);
            if (reg == -2) { fprintf(stderr, "c251 isel: %s 实参 %d 宽度>16位 M3 支持\n", fname, i); fail = 1; break; }
            if (reg < 0) { fprintf(stderr, "c251 isel: %s 实参 %d 寄存器不足 (M3 栈传参)\n", fname, i); fail = 1; break; }
            abi_regs[nabi] = reg;
            abi_sz[nabi] = asz;
            nabi++;
        }
        /* ②' 预转存：源值寄存器命中其他实参的 ABI 目标 → 溢出到独立槽并解除寄存器绑定
         *   （装载自动走槽路径，彻底避免逆序装载互相覆盖） */
        for (int i = 0; i < nargs && !fail; i++) {
            ValueName av = *(ValueName*)list_get(ins->args, i);
            int r = isel_value_reg(ctx, av);
            if (r < 0 || r == abi_regs[i]) continue;  /* 常量/槽 或 已就位 */
            int hit = 0;
            for (int j = 0; j < nargs; j++)
                if (abi_regs[j] == r || abi_regs[j] == r + 1) { hit = 1; break; }
            if (!hit) continue;                       /* 源不在 ABI 目标集，直接装载安全 */
            char *sp = c251_alloc_spill(ctx, av);
            char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
            isel_emit(isel, "MOV", sp, rbuf);
            char *k = c251_key(av);
            dict_remove(ctx->value_to_reg, k); free(k);
            isel->reg_val[r/2] = -1;
            /* 解除绑定后 load_* 自动走槽路径 */
        }
        /* ① 活值压栈（递归安全：内层调用覆盖寄存器后，外层经 POP 恢复；
         *    预转存已解除绑定的 WR 不压栈，restore 对称） */
        save_live_regs_stack(isel);
        /* ② spill 槽压栈（仅自递归调用：避免所有调用都压栈导致超时/栈溢出） */
        int is_self_recursive = ctx->current_func && ctx->current_func->name
            && fname && strcmp(ctx->current_func->name, fname) == 0;
        List *spill_slots = is_self_recursive ? save_spill_slots_stack(isel) : NULL;
        /* ③ 逆序装载（源已搬离 ABI 目标集，装载不会互相覆盖） */
        for (int i = nargs - 1; i >= 0 && !fail; i--) {
            ValueName av = *(ValueName*)list_get(ins->args, i);
            int reg = abi_regs[i], asz = abi_sz[i];
            if (asz <= 1) load_u8_to_r(isel, av, reg);
            else           load_value_to_wr(isel, av, reg);
        }
        /* ③ 调用 */
        isel_emit(isel, "LCALL", fname, NULL);
        /* ④ 返回值暂存：u16 在 WR6（可能被恢复活值 POP 覆盖）；u8 在 A(R11) 不参与 POP，无需暂存 */
        bool r_u8 = ins->type && ins->type->size <= 1;
        char *ret_spill = NULL;
        if (ins->dest > 0 && !r_u8) {
            ret_spill = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", ret_spill, "WR6");
        }
        /* ⑤b 恢复 spill 槽（ret_spill 在快照后分配，不受影响）。
         * 必须先于活值恢复：save 顺序是①活值压栈→②spill 槽压栈（spill 在栈顶），
         * 所以 restore 必须②'先 POP spill 槽（栈顶）→①'再 POP 活值（栈底）。
         * 若顺序颠倒，spill 槽会取到活寄存器数据、活值会取到槽数据。 */
        restore_spill_slots_stack(isel, spill_slots);
        /* ⑤ 恢复活值 */
        restore_live_regs_stack(isel);
        /* ⑥ dest 物化（u8 从 A；u16 从 ret_spill=dest 槽） */
        if (ins->dest > 0) {
            int wr = isel_alloc_wr(isel, ins->dest);
            if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                if (r_u8) isel_emit(isel, "MOVZ", wbuf, "A");
                else isel_emit(isel, "MOV", wbuf, ret_spill);
            } else if (r_u8) {
                /* dest 溢出：u8 值在 A → MOVZ WRt,A 零扩展后 16 位写槽
                 * （大端：槽[0]=高=0, 槽[1]=低=A，与 load_u8_to_r 槽读取一致） */
                int t = isel_temp_wr(isel, -1, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), t);
                isel_emit(isel, "MOVZ", tbuf, "A");
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
            /* u16 且 dest 溢出：值已在 ret_spill=dest 槽，无需再操作 */
        }
        break;
    }
    case IROP_LOAD: {
        /* 真实寻址：ptr 是 ADDR 产物 → 查 value_to_addr 得符号名。
         * 宽度感知（D10 全大端）：char 目标 → 8 位读 Rm + MOVZ/MOVS 扩展；
         * int 目标 → 16 位 MOV WRj,SYM。 */
        ValueName ptr = src1_of(ins);
        char *sym = value_to_addr_lookup(ctx, ptr);
        int wr = isel_alloc_wr(isel, ins->dest);
        int dsz = value_size_of_ctx(ctx, ins->dest);
        /* 指针目标的 LOAD（`int *p = g_arr;` 中 v2 = load v1, v1=addr @g_arr）：
         * C 语义数组名衰减为地址——加载的是符号地址而非内存数据（MOV WRj,#sym）。
         * 仅当源是数组（sym 实际大小 > 指针 2 字节）才衰减；`*pp` 读指针变量（2 字节）
         * 应读内存值（MOV WRj,SYM），否则 `**pp` 错误物化地址 (0005-ifstmt FAIL)。
         * 注意用原始大小（sym_size_of 截断到 1/2，数组 10 字节会被误判为 2）。 */
        bool dest_is_ptr = (ins->type && ins->type->type == CTYPE_PTR);
        int sym_sz = 0;
        if (sym && ctx->sym_size) {
            int *s = (int*)dict_get(ctx->sym_size, (char*)sym);
            if (s) sym_sz = *s;
        }
        bool array_decay = dest_is_ptr && sym && sym_sz > 2;
        /* M3: sfr 直接地址读 — MOV A,dir8 + 转移到目标 (0xE5 xx); sbit 提取位 */
        if (sym && ctx->sfr_addr) {
            int saddr = 0, sbit = -1;
            if (sfr_lookup(ctx, sym, &saddr, &sbit)) {
                char dirdesc[32]; snprintf(dirdesc, sizeof(dirdesc), "0x%02X", saddr);
                int lo = (wr >= 0) ? wr : isel_temp_wr(isel, -1, -1);
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), lo);
                char rbuf[16]; snprintf(rbuf, sizeof(rbuf), "R%d", lo + 1);
                /* 读取 SFR 到 A, 再转 Rm (u8) */
                isel_emit(isel, "MOV", "A", dirdesc);
                isel_emit(isel, "MOV", rbuf, "A");
                if (sbit >= 0) {
                    /* sbit 读: A 右移 sbit 位, AND 1 → 0/1 */
                    for (int b = 0; b < sbit; b++) isel_emit(isel, "SRL", "A", NULL);
                    isel_emit(isel, "ANL", "A", "#1");
                    isel_emit(isel, "MOV", rbuf, "A");
                    isel_emit(isel, "MOVZ", wbuf, rbuf);
                } else if (dsz <= 1) {
                    if (value_decl_unsigned(ctx, ins->dest))
                        isel_emit(isel, "MOVZ", wbuf, rbuf);
                    else
                        isel_emit(isel, "MOVS", wbuf, rbuf);
                }
                if (wr < 0) {
                    char *sp = c251_alloc_spill(ctx, ins->dest);
                    isel_emit(isel, "MOV", sp, wbuf);
                }
                break;
            }
        }
        if (sym) {
            if (array_decay) {
                /* 指针 = &符号：物化地址立即数 */
                char saddr[64]; snprintf(saddr, sizeof(saddr), "#%s", sym);
                if (wr >= 0) {
                    char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                    isel_emit(isel, "MOV", wbuf, saddr);
                } else {
                    int tmp = isel_temp_wr(isel, -1, -1);
                    char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                    isel_emit(isel, "MOV", tbuf, saddr);
                    char *sp = c251_alloc_spill(ctx, ins->dest);
                    isel_emit(isel, "MOV", sp, tbuf);
                }
            } else if (dsz <= 1) {
                /* char: MOV R(lo+1),SYM (8 位读) → MOVZ/MOVS WRlo,R(lo+1) */
                int lo = (wr >= 0) ? wr : isel_temp_wr(isel, -1, -1);
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), lo);
                char rbuf[16]; snprintf(rbuf, sizeof(rbuf), "R%d", lo + 1);
                isel_emit(isel, "MOV", rbuf, sym);
                if (value_decl_unsigned(ctx, ins->dest))
                    isel_emit(isel, "MOVZ", wbuf, rbuf);
                else
                    isel_emit(isel, "MOVS", wbuf, rbuf);
                if (wr < 0) {
                    char *sp = c251_alloc_spill(ctx, ins->dest);
                    isel_emit(isel, "MOV", sp, wbuf);
                }
            } else if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                if (dsz > 2) {
                    /* long (4B): 16 位加载取低 16 位 (大端偏移 +2) (0046-inits: y=6) */
                    char symlo[64]; snprintf(symlo, sizeof(symlo), "(%s + 2)", sym);
                    isel_emit(isel, "MOV", wbuf, symlo);
                } else {
                    isel_emit(isel, "MOV", wbuf, sym);
                }
            } else {
                int tmp = isel_temp_wr(isel, -1, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                if (dsz > 2) {
                    char symlo[64]; snprintf(symlo, sizeof(symlo), "(%s + 2)", sym);
                    isel_emit(isel, "MOV", tbuf, symlo);
                } else {
                    isel_emit(isel, "MOV", tbuf, sym);
                }
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
        } else {
            /* 指针间接读: ptr 值 → WRk（16 位 EDATA 地址）→ MOV WRj,@WRk */
            int addr_wr = isel_temp_wr(isel, wr, -1);
            if (load_value_to_wr(isel, ptr, addr_wr) < 0) {
                /* ptr 未物化（如 OFFSET 产物，任务 2 实现）：兜底 dest=0，不产生未定义值 */
                if (wr >= 0) {
                    char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                    isel_emit(isel, "MOV", wbuf, "#0");
                } else {
                    int tmp = isel_temp_wr(isel, -1, -1);
                    char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                    isel_emit(isel, "MOV", tbuf, "#0");
                    char *sp = c251_alloc_spill(ctx, ins->dest);
                    isel_emit(isel, "MOV", sp, tbuf);
                }
                break;
            }
            char abuf[16]; wr_name(abuf, sizeof(abuf), addr_wr);
            char ind[32]; snprintf(ind, sizeof(ind), "@%s", abuf);
            if (dsz <= 1) {
                int lo = (wr >= 0) ? wr : isel_temp_wr(isel, addr_wr, -1);
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), lo);
                char rbuf[16]; snprintf(rbuf, sizeof(rbuf), "R%d", lo + 1);
                isel_emit(isel, "MOV", rbuf, ind);   /* 8 位间接读 */
                if (value_decl_unsigned(ctx, ins->dest))
                    isel_emit(isel, "MOVZ", wbuf, rbuf);
                else
                    isel_emit(isel, "MOVS", wbuf, rbuf);
                if (wr < 0) {
                    char *sp = c251_alloc_spill(ctx, ins->dest);
                    isel_emit(isel, "MOV", sp, wbuf);
                }
            } else if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                isel_emit(isel, "MOV", wbuf, ind);    /* 16 位间接读 */
            } else {
                int tmp = isel_temp_wr(isel, addr_wr, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                isel_emit(isel, "MOV", tbuf, ind);
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
        }
        break;
    }
    case IROP_STORE: {
        /* ssa_pass 优化格式: labels[0]="@sym", 值在 imm.ival（无 args）——store @g, const。
         * 宽度按目标符号 size：char → 8 位写，int → 16 位写（防破坏邻居）。 */
        if (ins->labels && list_len(ins->labels) > 0) {
            const char *lab = (const char*)list_get(ins->labels, 0);
            if (lab && lab[0] == '@') {
                /* 局部变量名转换：优化格式 @x 用原始名，须映射到函数作用域槽 __loc_fn_x
                 * （与 ADDR 处理一致，否则 store 到未注册符号 x → unknown symbol） */
                const char *raw = lab + 1;
                /* M3: sfr 直接写 — store @P0, const → MOV dir8,A; sbit 用 RMW */
                if (ctx->sfr_addr && dict_get(ctx->sfr_addr, (char*)raw)) {
                    int saddr = 0, sbit = -1;
                    sfr_lookup(ctx, raw, &saddr, &sbit);
                    char dirdesc[32]; snprintf(dirdesc, sizeof(dirdesc), "0x%02X", saddr);
                    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFF);
                    isel_emit(isel, "MOV", "A", imm);
                    if (sbit >= 0) {
                        isel_emit(isel, "MOV", "R0", "A");
                        for (int b = 0; b < sbit; b++) isel_emit(isel, "SLL", "R0", NULL);
                        isel_emit(isel, "MOV", "A", dirdesc);
                        char clr[16]; snprintf(clr, sizeof(clr), "#0x%02X", (unsigned char)~(1 << sbit));
                        isel_emit(isel, "ANL", "A", clr);
                        isel_emit(isel, "ORL", "A", "R0");
                        isel_emit(isel, "MOV", dirdesc, "A");
                    } else {
                        isel_emit(isel, "MOV", dirdesc, "A");
                    }
                    break;
                }
                char sym[160];
                if (!c251_obj_has_sym(ctx->obj, raw)) {
                    const char *fn = (ctx->current_func && ctx->current_func->name)
                        ? ctx->current_func->name : "?";
                    snprintf(sym, sizeof(sym), "__loc_%s_%s", fn, raw);
                } else {
                    snprintf(sym, sizeof(sym), "%s", raw);
                }
                int ssz = sym_size_of(ctx, sym);
                int tmp = isel_temp_wr(isel, -1, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                if (ssz <= 1) {
                    char rbuf[16]; snprintf(rbuf, sizeof(rbuf), "R%d", tmp + 1);
                    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFF);
                    isel_emit(isel, "MOV", rbuf, imm);
                    isel_emit(isel, "MOV", sym, rbuf);
                } else {
                    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
                    isel_emit(isel, "MOV", tbuf, imm);
                    isel_emit(isel, "MOV", sym, tbuf);
                }
                break;
            }
        }
        /* store ptr, val → MOV SYMBOL,WRj（宽度按目标符号 size） */
        ValueName ptr = src1_of(ins), val = src2_of(ins);
        char *sym = value_to_addr_lookup(ctx, ptr);
        /* M3: sfr 直接地址写 — 值→A→MOV dir8,A (0xF5 xx); sbit 用 RMW */
        if (sym && ctx->sfr_addr) {
            int saddr = 0, sbit = -1;
            if (sfr_lookup(ctx, sym, &saddr, &sbit)) {
                char dirdesc[32]; snprintf(dirdesc, sizeof(dirdesc), "0x%02X", saddr);
                int r = isel_value_reg(ctx, val);
                int vsz = value_size_of_ctx(ctx, val);
                if (r >= 0) {
                    char rlo[8]; snprintf(rlo, sizeof(rlo), "R%d", r + 1);
                    isel_emit(isel, "MOV", "A", rlo);
                } else {
                    int tmp = isel_temp_wr(isel, -1, -1);
                    char tlo[8]; snprintf(tlo, sizeof(tlo), "R%d", tmp + 1);
                    if (load_value_to_wr(isel, val, tmp) == 0)
                        isel_emit(isel, "MOV", "A", tlo);
                    else {
                        fprintf(stderr, "c251 isel: sfr store 值无法装载 (v%d)\n", val);
                        break;
                    }
                }
                if (sbit >= 0) {
                    /* sbit 写 (RMW): 新值 A → R0 (位值), 读 SFR → 清位 → OR 位值 → 写回 */
                    isel_emit(isel, "MOV", "R0", "A");           /* 位值 0/1 */
                    if (sbit > 0) { /* 位值左移 sbit 位 */
                        for (int b = 0; b < sbit; b++) isel_emit(isel, "SLL", "R0", NULL);
                    }
                    isel_emit(isel, "MOV", "A", dirdesc);          /* 读当前 SFR */
                    char clr[16]; snprintf(clr, sizeof(clr), "#0x%02X", (unsigned char)~(1 << sbit));
                    isel_emit(isel, "ANL", "A", clr);              /* 清位 */
                    isel_emit(isel, "ORL", "A", "R0");            /* OR 位值 */
                    isel_emit(isel, "MOV", dirdesc, "A");          /* 写回 */
                } else {
                    isel_emit(isel, "MOV", dirdesc, "A");
                }
                break;
            }
        }
        if (!sym) {
            /* 指针间接写: ptr 值 → WRk（16 位 EDATA 地址）→ 值 → MOV @WRk,WRj */
            int addr_wr = isel_temp_wr(isel, -1, -1);
            if (load_value_to_wr(isel, ptr, addr_wr) < 0) {
                fprintf(stderr, "c251 isel: STORE 指针值无法装载 (v%d)\n", ptr);
                break;
            }
            char abuf[16]; wr_name(abuf, sizeof(abuf), addr_wr);
            char ind[32]; snprintf(ind, sizeof(ind), "@%s", abuf);
            int r = isel_value_reg(ctx, val);
            int vsz = value_size_of_ctx(ctx, val);
            if (r >= 0) {
                if (vsz <= 1) {
                    int t = isel_temp_wr(isel, r, addr_wr);
                    char tlo[16]; snprintf(tlo, sizeof(tlo), "R%d", t + 1);
                    char rlo[16]; snprintf(rlo, sizeof(rlo), "R%d", r + 1);
                    isel_emit(isel, "MOV", tlo, rlo);
                    isel_emit(isel, "MOV", ind, tlo);   /* 8 位间接写 */
                } else {
                    char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
                    isel_emit(isel, "MOV", ind, rbuf);  /* 16 位间接写 */
                }
            } else {
                int tmp = isel_temp_wr(isel, addr_wr, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                if (load_value_to_wr(isel, val, tmp) == 0) {
                    if (vsz <= 1) {
                        char tlo[16]; snprintf(tlo, sizeof(tlo), "R%d", tmp + 1);
                        isel_emit(isel, "MOV", ind, tlo);
                    } else {
                        isel_emit(isel, "MOV", ind, tbuf);
                    }
                } else {
                    fprintf(stderr, "c251 isel: STORE 值未物化 (v%d)\n", val);
                }
            }
            break;
        }
        int ssz = sym_size_of(ctx, sym);
        int r = isel_value_reg(ctx, val);
        if (r >= 0) {
            char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
            if (ssz <= 1) {
                /* 8 位写：值低字节 R(r+1)（WR 大端）→ 临时低字节 → MOV SYM,R */
                int t = isel_temp_wr(isel, r, -1);
                char tlo[16]; snprintf(tlo, sizeof(tlo), "R%d", t + 1);
                char rlo[16]; snprintf(rlo, sizeof(rlo), "R%d", r + 1);
                isel_emit(isel, "MOV", tlo, rlo);
                isel_emit(isel, "MOV", sym, tlo);
            } else {
                isel_emit(isel, "MOV", sym, rbuf);
            }
        } else {
            /* 值未物化（常量/溢出槽）：加载到临时再存 */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            if (load_value_to_wr(isel, val, tmp) == 0) {
                if (ssz <= 1) {
                    char tlo[16]; snprintf(tlo, sizeof(tlo), "R%d", tmp + 1);
                    isel_emit(isel, "MOV", sym, tlo);
                } else {
                    isel_emit(isel, "MOV", sym, tbuf);
                }
            } else {
                fprintf(stderr, "c251 isel: STORE 值未物化 (v%d)\n", val);
            }
        }
        break;
    }
    case IROP_ADDR: {
        /* 符号名在 labels[0]（带 '@' 前缀），去前缀后记录 dest→符号名。
         * 局部变量（数组/结构体等需内存寻址）首次 ADDR 时分配 EDATA 槽并注册符号：
         * 大小取 mem_type->size（addr 对象完整类型）；已存在符号（全局/已分配）跳过。 */
        const char *sym = (ins->labels && list_len(ins->labels) > 0)
            ? (const char*)list_get(ins->labels, 0) : NULL;
        if (sym && sym[0] == '@') sym++;
        if (sym && sym[0]) {
            /* M3: sfr 符号 — 特殊功能寄存器 (直接地址), 不建局部槽,
             * value_to_addr 直接用原名 (STORE/LOAD 查 sfr_addr 生成 dir8 访问) */
            if (ctx->sfr_addr && dict_get(ctx->sfr_addr, sym)) {
                dict_put(ctx->value_to_addr, c251_key(ins->dest), strdup(sym));
                break;
            }
            /* 全局符号（已注册）直接用原名；局部变量用函数名作用域修饰避免跨函数冲突 */
            if (!c251_obj_has_sym(ctx->obj, sym)) {
                char locname[128];
                const char *fn = (ctx->current_func && ctx->current_func->name)
                    ? ctx->current_func->name : "?";
                snprintf(locname, sizeof(locname), "__loc_%s_%s", fn, sym);
                if (!c251_obj_has_sym(ctx->obj, locname)) {
                    int sz = (ins->mem_type && ins->mem_type->size > 0) ? ins->mem_type->size : 2;
                    int sec_idx = obj_find_or_add_section(ctx->obj, "?ED?", SEC_EDATA, 1);
                    Section *sec = obj_get_section(ctx->obj, sec_idx);
                    if (sec->bytes_len == 0) {
                        section_append_zeros(sec, C251_EDATA_BASE);
                    }
                    int off = sec->bytes_len;
                    obj_add_symbol(ctx->obj, locname, SYM_DATA, sec_idx, off, sz, SYM_FLAG_LOCAL);
                    section_append_zeros(sec, sz);
                }
                dict_put(ctx->value_to_addr, c251_key(ins->dest), strdup(locname));
            } else {
                dict_put(ctx->value_to_addr, c251_key(ins->dest), strdup(sym));
            }
        }
        break;
    }
    case IROP_OFFSET: {
        /* v: ptr = offset base, index, elem_size
         * 定义时把元素地址物化到 dest 寄存器（懒物化的 ADDR 不可用——地址是计算值）：
         *   MOV WRj,#base_sym（或 base 已在寄存器）→ ADD WRj,#idx*size（常量）
         *   / SLL(2^shift) + ADD WRj,WRk（寄存器 index）
         * 后续 LOAD/STORE 经任务 1 的 @WRj 间接路径消费 dest 寄存器。
         * 元素 size 仅支持 1/2/4/8（2 的幂，SLL 实现）；其它报错提示。 */
        int size = (int)ins->imm.ival;
        if (size < 1) size = 1;
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            /* 1) 基址物化到 wr（ADDR 产物 → MOV WRj,#sym；嵌套 OFFSET → 其 dest 寄存器已物化） */
            ValueName base = src1_of(ins);
            if (load_value_to_wr(isel, base, wr) < 0) {
                fprintf(stderr, "c251 isel: OFFSET base 无法物化 (v%d)\n", base);
                isel_emit(isel, "MOV", wbuf, "#0");
                break;
            }
            /* 2) index 偏移 */
            if (ins->labels && list_len(ins->labels) >= 2) {
                char *tag = (char*)list_get(ins->labels, 0);
                if (tag && strcmp(tag, "imm") == 0) {
                    /* 常量 index（ssa_pass 约定: labels[1] = 十进制字符串） */
                    char *ims = (char*)list_get(ins->labels, 1);
                    long idx = ims ? strtol(ims, NULL, 10) : 0;
                    long off = idx * size;
                    if (off != 0) {
                        char imm[32]; snprintf(imm, sizeof(imm), "#%ld", off & 0xFFFF);
                        isel_emit(isel, "ADD", wbuf, imm);
                    }
                    break;
                }
            }
            ValueName idxv = src2_of(ins);
            if (idxv >= 0) {
                /* 用独立 temp 物化 index 再乘——SLL 就地修改会破坏共享 index 的持久寄存器
                 * （t2: 两个 OFFSET 共享 v1=const 2，第一次 SLL 2→4，第二次 4→8 地址错） */
                int idxr = isel_temp_wr(isel, wr, -1);
                if (load_value_to_wr(isel, idxv, idxr) == 0) {
                    char ibuf[16]; wr_name(ibuf, sizeof(ibuf), idxr);
                    /* index * size：2 的幂用 SLL 展开 */
                    int sz = size, shift = 0;
                    while (sz > 1 && (sz & 1) == 0) { shift++; sz >>= 1; }
                    if (sz == 1) {
                        for (int i = 0; i < shift; i++) isel_emit(isel, "SLL", ibuf, NULL);
                    } else {
                        fprintf(stderr, "c251 isel: OFFSET 非2幂元素大小 %d (M2.5 简化)\n", size);
                    }
                    isel_emit(isel, "ADD", wbuf, ibuf);
                    break;
                }
                fprintf(stderr, "c251 isel: OFFSET index 无法物化 (v%d)\n", idxv);
            }
        } else {
            /* 寄存器不足：temp 算地址，结果存溢出槽 */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            ValueName base = src1_of(ins);
            if (load_value_to_wr(isel, base, tmp) < 0) {
                fprintf(stderr, "c251 isel: OFFSET base 无法物化 (v%d)\n", base);
                isel_emit(isel, "MOV", tbuf, "#0");
            } else {
                if (ins->labels && list_len(ins->labels) >= 2) {
                    char *tag = (char*)list_get(ins->labels, 0);
                    if (tag && strcmp(tag, "imm") == 0) {
                        char *ims = (char*)list_get(ins->labels, 1);
                        long idx = ims ? strtol(ims, NULL, 10) : 0;
                        long off = idx * size;
                        if (off != 0) {
                            char imm[32]; snprintf(imm, sizeof(imm), "#%ld", off & 0xFFFF);
                            isel_emit(isel, "ADD", tbuf, imm);
                        }
                    }
                } else {
                    ValueName idxv = src2_of(ins);
                    if (idxv >= 0) {
                        int idxr = isel_temp_wr(isel, tmp, -1);
                        if (load_value_to_wr(isel, idxv, idxr) == 0) {
                            char ibuf[16]; wr_name(ibuf, sizeof(ibuf), idxr);
                            int sz = size, shift = 0;
                            while (sz > 1 && (sz & 1) == 0) { shift++; sz >>= 1; }
                            if (sz == 1) {
                                for (int i = 0; i < shift; i++) isel_emit(isel, "SLL", ibuf, NULL);
                            }
                            isel_emit(isel, "ADD", tbuf, ibuf);
                        }
                    }
                }
            }
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_ZEXT: case IROP_SEXT: case IROP_TRUNC: case IROP_INTTOPTR: {
        /* M2：宽度转换按拷贝处理（16 位值域内 zext/sext/trunc 无操作）；
         * dest 独立寄存器/槽，避免与 src 共享寄存器导致死值释放冲突 */
        ValueName s = src1_of(ins);
        if (s < 0) break;
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s, wr);
        } else {
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            if (load_value_to_wr(isel, s, tmp) == 0) {
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
        }
        break;
    }
    case IROP_JMP: {
        /* labels[0] = "block<id>"（无条件跳转目标） */
        const char *lbl = (ins->labels && list_len(ins->labels) > 0)
            ? (const char*)list_get(ins->labels, 0) : NULL;
        int tid = parse_block_id(lbl);
        if (tid < 0) { fprintf(stderr, "c251 isel: JMP 目标无法解析: %s\n", lbl ? lbl : "?"); break; }
        emit_phi_copies(isel, tid);
        char t[32]; block_label_name(t, sizeof(t), tid);
        isel_emit(isel, "SJMP", t, NULL);
        break;
    }
    case IROP_BR: {
        /* args[0] = 条件值; labels[0] = 真跳转, labels[1] = 假跳转 */
        ValueName cond = src1_of(ins);
        const char *tl = (ins->labels && list_len(ins->labels) > 0)
            ? (const char*)list_get(ins->labels, 0) : NULL;
        const char *fl = (ins->labels && list_len(ins->labels) > 1)
            ? (const char*)list_get(ins->labels, 1) : NULL;
        int tid = parse_block_id(tl), fid = parse_block_id(fl);
        if (tid < 0 || fid < 0) {
            fprintf(stderr, "c251 isel: BR 目标无法解析: %s / %s\n", tl ? tl : "?", fl ? fl : "?");
            break;
        }
        /* 条件为常量 → 直接单边跳转（suite 10/11/12 常量折叠后大量触发） */
        int64_t cv = 0; bool cond_const = false;
        if (cond >= 0) {
            char *k = c251_key(cond);
            int64_t *cp = (int64_t*)dict_get(ctx->value_to_const, k);
            free(k);
            if (cp) { cv = *cp; cond_const = true; }
        } else if (has_imm_label(ins)) {
            cv = ins->imm.ival; cond_const = true;
        }
        if (cond_const) {
            int go_t = (cv != 0);
            emit_phi_copies(isel, go_t ? tid : fid);
            char t[32]; block_label_name(t, sizeof(t), go_t ? tid : fid);
            isel_emit(isel, "SJMP", t, NULL);
            break;
        }
        /* BR 免物化：条件值命中紧邻比较的 hint（比较指令已发 CMP，直接 Jcc）。
         * 模式 B（NE dest,0 → BR）中 BR 条件 = NE 结果（br_hint_ne_skip）。 */
        if (isel->br_hint_cond >= 0
            && (cond == isel->br_hint_cond || cond == isel->br_hint_ne_skip)) {
            emit_phi_copies(isel, tid);
            char t[32]; block_label_name(t, sizeof(t), tid);
            isel_emit(isel, isel->br_hint_jump, t, NULL);
            emit_phi_copies(isel, fid);
            char f[32]; block_label_name(f, sizeof(f), fid);
            isel_emit(isel, "SJMP", f, NULL);
            isel->br_hint_cond = -1;
            isel->br_hint_ne_skip = -1;
            break;
        }
        /* 物化条件 → CMP #0 → JNE 真; SJMP 假 */
        int r = isel_value_reg(ctx, cond);
        if (r < 0) {
            r = isel_temp_wr(isel, -1, -1);
            if (load_value_to_wr(isel, cond, r) < 0) {
                fprintf(stderr, "c251 isel: BR 条件无法物化 (v%d)\n", cond);
                break;
            }
        }
        char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
        isel_emit(isel, "CMP", rbuf, "#0");
        emit_phi_copies(isel, tid);
        char t[32]; block_label_name(t, sizeof(t), tid);
        isel_emit(isel, "JNE", t, NULL);
        emit_phi_copies(isel, fid);
        char f[32]; block_label_name(f, sizeof(f), fid);
        isel_emit(isel, "SJMP", f, NULL);
        break;
    }
    case IROP_SELECT: {
        /* args = [cond, v_true, v_false]；常量参数被 ssa_pass 内联到 labels:
         * "imm1=<val>" / "imm2=<val>"（args 对应位置已替换为 0） */
        ValueName cond = src1_of(ins), v_true = src2_of(ins), v_false = src3_of(ins);
        long long t_imm = 0, f_imm = 0; bool t_is_imm = false, f_is_imm = false;
        if (ins->labels) {
            for (Iter lit = list_iter(ins->labels); !iter_end(lit);) {
                const char *l = iter_next(&lit);
                if (l && strncmp(l, "imm1=", 5) == 0) { t_imm = atoll(l + 5); t_is_imm = true; }
                if (l && strncmp(l, "imm2=", 5) == 0) { f_imm = atoll(l + 5); f_is_imm = true; }
            }
        }
        int wr = isel_alloc_wr(isel, ins->dest);
        char *lbl1 = isel_new_label(isel, "?S"), *lbl2 = isel_new_label(isel, "?S");
        int r = isel_value_reg(ctx, cond);
        if (r < 0) {
            /* 条件临时寄存器避开 dest（防 forced-spill 夺走 dest 寄存器） */
            r = isel_temp_wr(isel, wr, -1);
            if (load_value_to_wr(isel, cond, r) < 0) {
                fprintf(stderr, "c251 isel: SELECT 条件无法物化 (v%d)\n", cond);
                break;
            }
        }
        char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
        isel_emit(isel, "CMP", rbuf, "#0");
        isel_emit(isel, "JNE", lbl1, NULL);
        /* 假分支: dest = v_false（或 imm2） */
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            if (f_is_imm) { char imm[32]; snprintf(imm, sizeof(imm), "#%lld", f_imm & 0xFFFF); isel_emit(isel, "MOV", wbuf, imm); }
            else if (v_false == 0) { /* undef 且无 imm2 标签 → 显式报错 + 兜底，不静默用 undef */
                fprintf(stderr, "c251 isel: SELECT 假分支值 undef (v_true=%d)\n", v_true);
                isel_emit(isel, "MOV", wbuf, "#0");
            } else if (load_value_to_wr(isel, v_false, wr) < 0) {
                fprintf(stderr, "c251 isel: SELECT 假分支无法加载 (v%d)\n", v_false);
                isel_emit(isel, "MOV", wbuf, "#0");
            }
        } else {
            int tmp = isel_temp_wr(isel, r, -1); /* 避开条件寄存器 */
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            if (f_is_imm) { char imm[32]; snprintf(imm, sizeof(imm), "#%lld", f_imm & 0xFFFF); isel_emit(isel, "MOV", tbuf, imm); }
            else if (v_false == 0) {
                fprintf(stderr, "c251 isel: SELECT 假分支值 undef (v_true=%d)\n", v_true);
                isel_emit(isel, "MOV", tbuf, "#0");
            } else if (load_value_to_wr(isel, v_false, tmp) < 0) {
                fprintf(stderr, "c251 isel: SELECT 假分支无法加载 (v%d)\n", v_false);
                isel_emit(isel, "MOV", tbuf, "#0");
            }
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        isel_emit(isel, "SJMP", lbl2, NULL);
        isel_emit_label(isel, lbl1);
        /* 真分支: dest = v_true（或 imm1） */
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            if (t_is_imm) { char imm[32]; snprintf(imm, sizeof(imm), "#%lld", t_imm & 0xFFFF); isel_emit(isel, "MOV", wbuf, imm); }
            else if (v_true == 0) { /* undef 且无 imm1 标签 → 显式报错 + 兜底 */
                fprintf(stderr, "c251 isel: SELECT 真分支值 undef (v_false=%d)\n", v_false);
                isel_emit(isel, "MOV", wbuf, "#0");
            } else if (load_value_to_wr(isel, v_true, wr) < 0) {
                fprintf(stderr, "c251 isel: SELECT 真分支无法加载 (v%d)\n", v_true);
                isel_emit(isel, "MOV", wbuf, "#0");
            }
        } else {
            int tmp = isel_temp_wr(isel, r, -1); /* 避开条件寄存器 */
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            if (t_is_imm) { char imm[32]; snprintf(imm, sizeof(imm), "#%lld", t_imm & 0xFFFF); isel_emit(isel, "MOV", tbuf, imm); }
            else if (v_true == 0) {
                fprintf(stderr, "c251 isel: SELECT 真分支值 undef (v_false=%d)\n", v_false);
                isel_emit(isel, "MOV", tbuf, "#0");
            } else if (load_value_to_wr(isel, v_true, tmp) < 0) {
                fprintf(stderr, "c251 isel: SELECT 真分支无法加载 (v%d)\n", v_true);
                isel_emit(isel, "MOV", tbuf, "#0");
            }
            char *sp = c251_value_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        isel_emit_label(isel, lbl2);
        free(lbl1); free(lbl2);
        break;
    }
    default:
        break; /* M2 扩展 */
    }
}

void isel_block(ISelContext* isel, Block* block) {
    if (!isel || !block) return;
    isel->current_block_id = block->id;

    /* BR 免物化 hint 块级重置（hint 只在块内紧邻有效） */
    isel->br_hint_cond = -1;
    isel->br_hint_ne_skip = -1;

    /* 块标签：L<id>: */
    char lbl[32];
    block_label_name(lbl, sizeof(lbl), block->id);
    isel_emit_label(isel, lbl);

    /* PHI：块首为每个 phi dest 分配 EDATA 槽（边缘拷贝目标）；值在使用处从槽加载 */
    if (block->phis) {
        for (Iter pit = list_iter(block->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (phi && phi->op == IROP_PHI && phi->dest >= 0) {
                c251_alloc_spill(isel->ctx, phi->dest);
            }
        }
    }

    /* 构建块指令视图（alloc_wr/死值扫描需要） */
    int n = list_len(block->instrs);
    Instr **arr = malloc(sizeof(Instr*) * (n > 0 ? n : 1));
    int idx = 0;
    for (Iter it = list_iter(block->instrs); !iter_end(it);) {
        arr[idx++] = iter_next(&it);
    }
    isel->block_instrs = arr;
    isel->block_instr_count = idx;
    for (int i = 0; i < idx; i++) {
        isel->block_instr_pos = i;
        isel_instr(isel, arr[i], NULL);
    }
    isel->block_instrs = NULL;
    free(arr);
}

void isel_function(C251GenContext* ctx, Func* func) {
    if (!ctx || !func) return;
    if (ctx->value_to_reg) { dict_free(ctx->value_to_reg, free); ctx->value_to_reg = make_dict(NULL); }
    if (ctx->value_to_const) { dict_free(ctx->value_to_const, free); ctx->value_to_const = make_dict(NULL); }
    if (ctx->value_to_addr) { dict_free(ctx->value_to_addr, free); ctx->value_to_addr = make_dict(NULL); }
    /* value_to_spill 跨函数保留（EDATA 槽可复用；槽符号持续有效） */
    ctx->label_counter = 0;   /* 每函数重置寄存器分配计数器（多函数编译必需） */

    /* 预扫描跨块活值（死值释放的安全边界） */
    Dict *global_live = compute_global_live(func);

    int sec_idx = obj_find_or_add_section(ctx->obj, "?PR?", SEC_CODE, 1);
    Section* sec = obj_get_section(ctx->obj, sec_idx);
    int flags = SYM_FLAG_GLOBAL;
    obj_add_symbol(ctx->obj, func->name, SYM_FUNC, sec_idx, sec->size, 0, flags);
    ctx->current_func = func;

    /* 预扫描常量（phi 参数可能是 BR 后死代码位置的 CONST，指令处理顺序不可靠） */
    for (Iter pbit = list_iter(func->blocks); !iter_end(pbit);) {
        Block *pb = iter_next(&pbit);
        if (!pb) continue;
        for (Iter piit = list_iter(pb->instrs); !iter_end(piit);) {
            Instr *pi = iter_next(&piit);
            if (pi && pi->op == IROP_CONST && pi->dest >= 0) {
                char *pk = c251_key(pi->dest);
                if (!dict_get(ctx->value_to_const, pk)) {
                    int64_t *cv = malloc(sizeof(int64_t)); *cv = pi->imm.ival;
                    dict_put(ctx->value_to_const, pk, cv);
                } else { free(pk); }
            }
        }
    }

    ISelContext isel = {0};
    isel.ctx = ctx;
    isel.sec = sec;
    isel.label_counter = 0;
    isel.next_wr = 0;
    for (int i = 0; i < 4; i++) isel.reg_val[i] = -1;
    isel.global_live = global_live;
    isel.block_map = make_dict(NULL);
    /* Keil ABI 参数分配状态（每函数重置） */
    isel.param_counter = 0;
    memset(isel.param_used, 0, sizeof(isel.param_used));
    isel.param_u8i = 0;
    isel.param_u16i = 0;
    /* 预计算全部参数的 ABI 寄存器表（声明序；PARAM 指令查表消费，保证与调用方装载同序） */
    isel.param_abi_count = 0;
    isel.param_abi_nbytes = 0;
    if (func->param_types) {
        for (Iter pit = list_iter(func->param_types); !iter_end(pit);) {
            Ctype *pt = iter_next(&pit);
            int psz = (pt && pt->size > 1) ? 2 : 1;
            int preg = abi_param_reg(isel.param_used, psz, &isel.param_u8i, &isel.param_u16i);
            int idx = isel.param_abi_count;
            isel.param_abi_reg[idx] = preg;
            isel.param_abi_sz[idx] = psz;
            isel.param_abi_count++;
            if (preg >= 0) {
                isel.param_abi_bytes[isel.param_abi_nbytes++] = preg;
                if (psz > 1) isel.param_abi_bytes[isel.param_abi_nbytes++] = preg + 1;
            }
            if (isel.param_abi_count >= 16) break;
        }
    }
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block *blk = iter_next(&bit);
        char key[32]; snprintf(key, sizeof(key), "%d", blk->id);
        dict_put(isel.block_map, strdup(key), blk);  /* dict_put 不复制 key，必须 strdup */
    }

    /* 函数标签 */
    char label[256];
    snprintf(label, sizeof(label), "_%s:", func->name);
    isel_emit(&isel, label, NULL, NULL);

    /* 中断函数 prolog: 保存 PSW + 全部 R0-R7 (Keil ISR 语义, 保护被中断的 main 现场)。
     * PUSH PSW(0xD0) → PUSH R0..R7; RETI 前 POP 逆序恢复。 */
    if (func->is_interrupt) {
        isel_emit(&isel, "PUSH", "0xD0", NULL);
        for (int rr = 0; rr < 8; rr++) {
            char rnm[8]; snprintf(rnm, sizeof(rnm), "R%d", rr);
            isel_emit(&isel, "PUSH", rnm, NULL);
        }
    }

    /* main: 初始化 SP 到 EDATA 高位 (Keil STARTUP 行为; 避免 RET 弹栈到寄存器区 0x07,
     * 也避免 WR6/R7 返回值污染 SP=7 的栈导致 sim251 ret_mismatch) */
    if (func->name && strcmp(func->name, "main") == 0) {
        isel_emit(&isel, "MOV", "SP", "#0xDF");
    }

    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }

    dict_free(isel.block_map, NULL);
    dict_free(global_live, free);
}
