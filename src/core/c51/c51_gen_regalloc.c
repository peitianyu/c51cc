#include "c51_gen.h"

struct Interval {
    int v;
    int start;
    int end;
    bool indir;
};

static int cmp_interval_start(const void *a, const void *b)
{
    const Interval *ia = (const Interval *)a;
    const Interval *ib = (const Interval *)b;
    if (ia->start != ib->start) return ia->start - ib->start;
    return ia->end - ib->end;
}

int parse_vreg_id(const char *arg, bool *is_indirect)
{
    if (is_indirect) *is_indirect = false;
    if (!arg) return -1;
    if (arg[0] == 'v' && arg[1] >= '0' && arg[1] <= '9')
        return atoi(arg + 1);
    if (arg[0] == '@' && arg[1] == 'v' && arg[2] >= '0' && arg[2] <= '9') {
        if (is_indirect) *is_indirect = true;
        return atoi(arg + 2);
    }
    return -1;
}

void regalloc_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;

    int max_v = -1;
    int ins_index = 0;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it); ++ins_index) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
            char *arg = iter_next(&ait);
            int v = parse_vreg_id(arg, NULL);
            if (v > max_v) max_v = v;
        }
    }
    if (max_v < 0) return;

    int count = max_v + 1;
    int *start = gen_alloc(sizeof(int) * count);
    int *end = gen_alloc(sizeof(int) * count);
    bool *need_indirect = gen_alloc(sizeof(bool) * count);
    for (int i = 0; i < count; ++i) { start[i] = -1; end[i] = -1; }

    ins_index = 0;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it); ++ins_index) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;
            if (start[v] < 0) start[v] = ins_index;
            end[v] = ins_index;
            if (indir) need_indirect[v] = true;
        }
    }

    Interval *intervals = gen_alloc(sizeof(Interval) * count);
    int interval_count = 0;
    for (int v = 0; v < count; ++v) {
        if (start[v] < 0) continue;
        intervals[interval_count++] = (Interval){v, start[v], end[v], need_indirect[v]};
    }
    if (interval_count == 0) return;

    qsort(intervals, (size_t)interval_count, sizeof(Interval), cmp_interval_start);

    int *reg_of = gen_alloc(sizeof(int) * count);
    int *spill_addr = gen_alloc(sizeof(int) * count);
    for (int i = 0; i < count; ++i) { reg_of[i] = -1; spill_addr[i] = -1; }

    int active_cap = count;
    int *active = gen_alloc(sizeof(int) * active_cap);
    int active_len = 0;

    for (int i = 0; i < interval_count; ++i) {
        Interval cur = intervals[i];
        for (int j = 0; j < active_len; ) {
            int v = active[j];
            if (end[v] < cur.start) {
                active[j] = active[active_len - 1];
                active_len--;
                continue;
            }
            ++j;
        }

        int reg = -1;
        if (cur.indir) {
            bool r0_used = false, r1_used = false;
            for (int j = 0; j < active_len; ++j) {
                int v = active[j];
                if (reg_of[v] == 0) r0_used = true;
                if (reg_of[v] == 1) r1_used = true;
            }
            if (!r0_used) reg = 0;
            else if (!r1_used) reg = 1;
        } else {
            for (int r = 2; r <= 6; ++r) {
                bool used = false;
                for (int j = 0; j < active_len; ++j) {
                    if (reg_of[active[j]] == r) { used = true; break; }
                }
                if (!used) { reg = r; break; }
            }
        }

        if (reg >= 0) {
            reg_of[cur.v] = reg;
            active[active_len++] = cur.v;
            continue;
        }

        int spill_candidate = -1;
        int spill_end = -1;
        for (int j = 0; j < active_len; ++j) {
            int v = active[j];
            if (cur.indir && reg_of[v] > 1) continue;
            if (!cur.indir && reg_of[v] < 2) continue;
            if (end[v] > spill_end) { spill_end = end[v]; spill_candidate = v; }
        }

        if (spill_candidate >= 0 && spill_end > cur.end) {
            spill_addr[spill_candidate] = 0x30 + spill_candidate;
            reg_of[cur.v] = reg_of[spill_candidate];
            reg_of[spill_candidate] = -1;
            for (int j = 0; j < active_len; ++j) {
                if (active[j] == spill_candidate) {
                    active[j] = active[active_len - 1];
                    active_len--;
                    break;
                }
            }
            active[active_len++] = cur.v;
        } else {
            spill_addr[cur.v] = 0x30 + cur.v;
        }
    }

    List *out = make_list();
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op || !ins->args) {
            list_push(out, ins);
            continue;
        }

        /* 检查是否是特殊指令（比较/跳转），它们需要在A中 */
        bool needs_a_reg = false;
        if (!strcmp(ins->op, "cjne") || !strcmp(ins->op, "jz") ||
            !strcmp(ins->op, "jnz") || !strcmp(ins->op, "anl") ||
            !strcmp(ins->op, "orl") || !strcmp(ins->op, "add") ||
            !strcmp(ins->op, "subb")) {
            needs_a_reg = true;
        }
        
        /* 收集需要在前面加载的参数 */
        int load_v = -1;
        int load_spill = -1;
        bool is_src_arg = false;
        int arg_pos = 0;
        
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++arg_pos) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;
            
            /* 如果这个虚拟寄存器被spill到内存，需要加载 */
            if (spill_addr[v] >= 0 && !indir) {
                load_v = v;
                load_spill = spill_addr[v];
                /* 判断是源操作数还是目标操作数 (arg_pos=0是目标) */
                is_src_arg = (arg_pos > 0 || ins->args->len == 1);
                break;
            }
        }
        
        /* 对于源操作数，在指令前生成加载 */
        if (load_v >= 0 && is_src_arg && needs_a_reg) {
            AsmInstr *load = gen_instr_new("mov");
            gen_instr_add_arg(load, "A");
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%02X", load_spill & 0xFF);
            gen_instr_add_arg(load, buf);
            list_push(out, load);
        }

        bool need_tmp = false;
        int tmp_spill = -1;
        int idx = 0;
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++idx) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;

            if (spill_addr[v] >= 0 && indir) {
                need_tmp = true;
                tmp_spill = spill_addr[v];
                char buf[16];
                snprintf(buf, sizeof(buf), "@r0");
                list_set(ins->args, idx, gen_strdup(buf));
                free(arg);
                continue;
            }

            char buf[16];
            if (spill_addr[v] >= 0) {
                /* 如果已经生成加载指令，替换为A */
                if (is_src_arg && needs_a_reg && v == load_v && idx > 0) {
                    snprintf(buf, sizeof(buf), "A");
                } else {
                    snprintf(buf, sizeof(buf), "0x%02X", spill_addr[v] & 0xFF);
                }
            } else if (reg_of[v] >= 0) {
                if (indir) snprintf(buf, sizeof(buf), "@r%d", reg_of[v]);
                else snprintf(buf, sizeof(buf), "r%d", reg_of[v]);
            } else {
                snprintf(buf, sizeof(buf), "r0");
            }
            list_set(ins->args, idx, gen_strdup(buf));
            free(arg);
        }

        if (need_tmp && tmp_spill >= 0) {
            AsmInstr *load = gen_instr_new("mov");
            gen_instr_add_arg(load, "r0");
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%02X", tmp_spill & 0xFF);
            gen_instr_add_arg(load, buf);
            list_push(out, load);
        }

        list_push(out, ins);
    }

    free(sec->asminstrs);
    sec->asminstrs = out;
}
