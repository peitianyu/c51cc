#include "c51_gen.h"

static bool instr_has_imm_tag(const Instr *ins, int *out) {
    if (!ins || !ins->labels || ins->labels->len < 1) return false;
    char *tag = (char *)list_get(ins->labels, 0);
    if (tag && strcmp(tag, "imm") == 0) {
        if (out) *out = (int)ins->imm.ival;
        return true;
    }
    return false;
}

static bool func_has_call(Func *f) {
    if (!f || !f->blocks) return false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i && i->op == IROP_CALL) return true;
        }
    }
    return false;
}

static bool v16_reg_mapped(ValueName v) {
    return g_v16_reg_map && v > 0 && dict_get(g_v16_reg_map, vreg_key(v)) != NULL;
}

static Instr *find_def_instr_in_block(Block *b, ValueName v) {
    if (!b || v == 0 || !b->instrs) return NULL;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (i && i->dest == v) return i;
    }
    return NULL;
}

static Instr *find_def_instr_in_func(Func *f, ValueName v) {
    if (!f || v == 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b->instrs) {
            for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (i && i->dest == v) return i;
            }
        }
        if (b->phis) {
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *p = iter_next(&jt);
                if (p && p->dest == v) return p;
            }
        }
    }
    return NULL;
}

static bool is_v16_candidate(Func *f, ValueName v) {
    Instr *def = find_def_instr_in_func(f, v);
    if (def && def->type && def->type->size >= 2) return true;
    if (!f || v == 0) return false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || !i->args) continue;
            for (int k = 0; k < i->args->len; ++k) {
                ValueName *arg = list_get(i->args, k);
                if (arg && *arg == v && i->type && i->type->size >= 2) return true;
            }
        }
    }
    return false;
}

static bool is_one_immediate(Instr *def) {
    int imm = 0;
    if (instr_has_imm_tag(def, &imm) && imm == 1) return true;
    if (!def->args) return false;
    for (int k = 0; k < def->args->len; ++k) {
        ValueName *av = list_get(def->args, k);
        if (!av || *av == 0) continue;
        Instr *cdef = find_def_instr_in_func(NULL, *av);
        if (cdef && cdef->op == IROP_CONST && cdef->imm.ival == 1) return true;
    }
    return false;
}

static void select_v16_reg_pairs(Func *f) {
    if (!f || !g_v16_reg_map || func_has_call(f)) return;

    int pairs[2][2] = {{7, 6}, {5, 4}};
    int picked = 0;

    for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
        Block *b = iter_next(&bit);
        if (!b || !b->phis) continue;
        for (Iter pit = list_iter(b->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (!phi || phi->op != IROP_PHI) continue;
            if (!is_v16_candidate(f, phi->dest) || v16_reg_mapped(phi->dest)) continue;

            bool is_loop_counter = false;
            List *update_vals = make_list();
            for (int i = 0; i < phi->args->len && i < phi->labels->len; ++i) {
                ValueName *arg = list_get(phi->args, i);
                char *lbl = list_get(phi->labels, i);
                if (!arg || !lbl) continue;
                Block *pred = find_block_by_label(f, lbl);
                if (!pred) continue;
                Instr *def = find_def_instr_in_block(pred, *arg);
                if (!def || (def->op != IROP_ADD && def->op != IROP_SUB)) continue;
                if (!is_one_immediate(def)) continue;
                if (!def->args || def->args->len < 1) continue;
                ValueName *lhs = list_get(def->args, 0);
                ValueName *rhs = (def->args->len > 1) ? list_get(def->args, 1) : NULL;
                if ((lhs && *lhs == phi->dest) || (rhs && *rhs == phi->dest)) {
                    is_loop_counter = true;
                    ValueName *p = gen_alloc(sizeof(ValueName));
                    *p = *arg;
                    list_push(update_vals, p);
                    break;
                }
            }

            if (!is_loop_counter) {
                list_free(update_vals);
                free(update_vals);
                continue;
            }

            V16RegPair *rp = gen_alloc(sizeof(V16RegPair));
            rp->lo = pairs[picked][0];
            rp->hi = pairs[picked][1];
            dict_put(g_v16_reg_map, vreg_key(phi->dest), rp);

            for (Iter uit = list_iter(update_vals); !iter_end(uit);) {
                ValueName *uv = iter_next(&uit);
                if (uv && *uv > 0) v16_alias_put(*uv, phi->dest);
            }

            list_free(update_vals);
            free(update_vals);
            if (++picked >= 2) return;
        }
    }
}

static int count_value_uses_func(Func *f, ValueName v) {
    int cnt = 0;
    if (!f || v == 0) return 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b->instrs) {
            for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *arg = list_get(i->args, k);
                    if (arg && *arg == v) cnt++;
                }
            }
        }
        if (b->phis) {
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *p = iter_next(&jt);
                if (!p || !p->args) continue;
                for (int k = 0; k < p->args->len; ++k) {
                    ValueName *arg = list_get(p->args, k);
                    if (arg && *arg == v) cnt++;
                }
            }
        }
    }
    return cnt;
}

static void prepare_phi_aliases(Func *f, Block *from) {
    if (!f || !from || !from->instrs || from->instrs->len == 0) return;
    Instr *term = (Instr *)list_get(from->instrs, from->instrs->len - 1);
    if (!term || !term->labels) return;

    char from_label[32];
    snprintf(from_label, sizeof(from_label), "block%d", from->id);

    int label_count = (term->op == IROP_BR) ? 2 : (term->op == IROP_JMP ? 1 : 0);
    for (int l = 0; l < label_count; ++l) {
        char *lbl = list_get(term->labels, l);
        Block *to = find_block_by_label(f, lbl);
        if (!to || !to->phis) continue;

        for (Iter pit = list_iter(to->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (!phi || phi->op != IROP_PHI || !phi->labels || !phi->args) continue;

            ValueName src_val = 0;
            int src_idx = -1;
            for (int i = 0; i < phi->labels->len && i < phi->args->len; ++i) {
                char *plbl = list_get(phi->labels, i);
                if (!plbl || strcmp(plbl, from_label) != 0) continue;
                ValueName *src = list_get(phi->args, i);
                if (!src) continue;
                src_val = *src;
                src_idx = i;
                break;
            }

            if (src_val == 0 || src_val == phi->dest || count_value_uses_func(f, src_val) > 1) continue;
            Instr *def = find_def_instr_in_block(from, src_val);
            if (!def) continue;

            int def_idx = -1;
            for (int di = 0; di < from->instrs->len; ++di) {
                if (list_get(from->instrs, di) == def) { def_idx = di; break; }
            }
            if (def_idx < 0 || def_idx != from->instrs->len - 2) continue;

            if (src_idx >= 0) {
                ValueName *srcp = list_get(phi->args, src_idx);
                if (srcp) *srcp = phi->dest;
            }
            def->dest = phi->dest;
            v16_alias_put(src_val, phi->dest);
        }
    }
}

static void emit_globals_from_ssa(ObjFile *obj, SSAUnit *unit) {
    if (!obj || !unit) return;
    for (Iter git = list_iter(unit->globals); !iter_end(git);)
        emit_global_data(obj, iter_next(&git));
}

static ObjFile *process_asm_blocks_from_ssa(SSAUnit *unit, ObjFile *obj) {
    if (!unit || !obj || !unit->asm_blocks || unit->asm_blocks->len == 0) return NULL;

    List *objs = make_list();
    list_push(objs, obj);

    for (Iter it = list_iter(unit->asm_blocks); !iter_end(it);) {
        char *text = iter_next(&it);
        if (!text || !*text) continue;

        char *err = NULL;
        int err_line = 0;
        ObjFile *aobj = c51_asm_from_text(text, &err, &err_line);
        if (!aobj) {
            fprintf(stderr, "asm block assemble failed at line %d: %s\n", err_line, err ? err : "(null)");
            free(err);
            exit(1);
        }
        free(err);

        for (Iter sit = list_iter(aobj->sections); !iter_end(sit);) {
            Section *s = iter_next(&sit);
            if (s) encode_section_bytes(aobj, s);
        }
        list_push(objs, aobj);
    }

    ObjFile *out = obj_link(objs);
    for (ListNode *n = objs->head; n; n = n->next) n->elem = NULL;
    list_free(objs);
    free(objs);
    return out;
}

static void cleanup_function_context(void) {
    dict_clear(g_addr_map);      g_addr_map = NULL;
    dict_clear(g_const_map);     g_const_map = NULL;
    dict_clear(g_v16_map);       g_v16_map = NULL;
    dict_clear(g_v16_reg_map);   g_v16_reg_map = NULL;
    dict_clear(g_v16_alias);     g_v16_alias = NULL;
    if (g_v16_base_label) { free(g_v16_base_label); g_v16_base_label = NULL; }
    if (g_val_type) {
        for (Iter it = list_iter(g_val_type->list); !iter_end(it);) {
            DictEntry *e = iter_next(&it);
            if (e) free(e->key);
        }
        dict_clear(g_val_type);
        g_val_type = NULL;
    }
}

static void process_function_ssa(Func *f, ObjFile *obj) {
    if (!f || !f->name || !obj) return;

    g_addr_map = make_dict(NULL);
    g_const_map = make_dict(NULL);
    g_val_type = make_dict(NULL);
    g_v16_map = make_dict(NULL);
    g_v16_reg_map = make_dict(NULL);
    g_v16_alias = make_dict(NULL);
    g_v16_next = 0;
    char v16_label[128];
    snprintf(v16_label, sizeof(v16_label), "__v16_%s", f->name);
    g_v16_base_label = gen_strdup(v16_label);

    select_v16_reg_pairs(f);

    char sec_name[128];
    snprintf(sec_name, sizeof(sec_name), ".text.%s", f->name);
    Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

    objfile_add_symbol(obj, (char *)f->name, SYM_FUNC, section_index_from_ptr(obj, sec), 0, 0, SYM_FLAG_GLOBAL);
    emit_label(sec, f->name);

    if (!f->is_interrupt && f->bank_id >= 0) {
        char ubuf[8];
        snprintf(ubuf, sizeof(ubuf), "%d", f->bank_id);
        emit_ins1(sec, ".using", ubuf);
    }

    if (f->is_interrupt) {
        char buf[16], bbuf[16];
        snprintf(buf, sizeof(buf), "%d", f->interrupt_id);
        emit_ins1(sec, ".interrupt", buf);
        if (f->bank_id >= 0) {
            snprintf(bbuf, sizeof(bbuf), "%d", f->bank_id);
            emit_ins1(sec, ".using", bbuf);
        }
        emit_interrupt_prologue(sec);
    }
    if (f->stack_size > 0)
        emit_frame_prologue(sec, f->stack_size);

    Block *last_block = NULL;
    for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
        Block *b = iter_next(&bit);
        if (!b) continue;
        last_block = b;
        char label[64];
        snprintf(label, sizeof(label), "L%s_%u", f->name, b->id);
        emit_label(sec, label);
        prepare_phi_aliases(f, b);
        for (Iter it = list_iter(b->instrs); !iter_end(it);)
            emit_instr(sec, iter_next(&it), f, b);
    }

    if (last_block) {
        bool has_ret = false;
        for (Iter it = list_iter(last_block->instrs); !iter_end(it);) {
            Instr *ins = iter_next(&it);
            if (ins && ins->op == IROP_RET) { has_ret = true; break; }
        }
        if (!has_ret) {
            if (f->stack_size > 0) emit_frame_epilogue(sec, f->stack_size);
            if (f->is_interrupt) {
                emit_interrupt_epilogue(sec);
                emit_ins0(sec, "reti");
            } else {
                emit_ins0(sec, "ret");
            }
        }
    }

    regalloc_section_asminstrs(sec);
    lower_section_asminstrs(sec);
    shrink_call_saves(sec);
    peephole_section_asminstrs(sec);
    remove_unused_labels(sec);
    fixup_short_jumps(sec);
    encode_section_bytes(obj, sec);

    if (g_v16_next > 0 && g_v16_base_label) {
        char v16_sec[128];
        snprintf(v16_sec, sizeof(v16_sec), ".data.v16.%s", f->name);
        Section *dsec = get_or_create_section(obj, v16_sec, SEC_DATA);
        int offset = dsec->bytes_len;
        section_append_zeros(dsec, g_v16_next);
        objfile_add_symbol(obj, g_v16_base_label, SYM_DATA, section_index_from_ptr(obj, dsec), offset, g_v16_next, SYM_FLAG_LOCAL);
    }

    cleanup_function_context();
}

ObjFile *c51_gen_from_ssa(void *ssa) {
    SSAUnit *unit = (SSAUnit *)ssa;
    if (!unit) return NULL;

    ObjFile *obj = objfile_new();
    g_mmio_map = make_dict(NULL);

    emit_globals_from_ssa(obj, unit);

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (f) process_function_ssa(f, obj);
    }

    dict_clear(g_mmio_map);
    g_mmio_map = NULL;

    ObjFile *asm_out = process_asm_blocks_from_ssa(unit, obj);
    return asm_out ? asm_out : obj;
}

/* === From c51_gen_utils.c === */
Dict *g_addr_map = NULL;
Dict *g_const_map = NULL;
Dict *g_mmio_map = NULL;
Dict *g_val_type = NULL;
Dict *g_v16_map = NULL;
Dict *g_v16_reg_map = NULL;
Dict *g_v16_alias = NULL;
int g_v16_next = 0x70;
char *g_v16_base_label = NULL;
int g_lower_id = 0;

void *gen_alloc(size_t size) {
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "c51_gen: out of memory\n");
        exit(1);
    }
    return p;
}

char *gen_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = gen_alloc(len);
    memcpy(d, s, len);
    return d;
}


bool is_ident(const char *s) {
    if (!s || !*s) return false;
    if (!isalpha((unsigned char)*s) && *s != '_') return false;
    for (const char *p = s + 1; *p; ++p) {
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    }
    return true;
}

bool parse_int_val(const char *s, int *out) {
    if (!s || !*s) return false;
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s || (end && *end != '\0')) return false;
    if (out) *out = (int)v;
    return true;
}

int parse_reg_rn(const char *s) {
    if (!s) return -1;
    if ((s[0] == 'r' || s[0] == 'R') && s[1] >= '0' && s[1] <= '7' && s[2] == '\0')
        return s[1] - '0';
    if ((s[0] == 'a' || s[0] == 'A') && (s[1] == 'r' || s[1] == 'R') &&
        s[2] >= '0' && s[2] <= '7' && s[3] == '\0')
        return s[2] - '0';
    return -1;
}

int parse_indirect_rn(const char *s) {
    if (!s || s[0] != '@' || s[1] != 'r' || s[2] < '0' || s[2] > '7' || s[3] != '\0') return -1;
    return s[2] - '0';
}

bool parse_immediate(const char *s, int *out) {
    return s && s[0] == '#' && parse_int_val(s + 1, out);
}

bool parse_direct(const char *s, int *out) {
    if (!s || !*s) return false;
    if (!strcmp(s, "B")) { if (out) *out = 0xF0; return true; }
    if (!strcmp(s, "A")) { if (out) *out = 0xE0; return true; }
    return parse_int_val(s, out);
}

bool parse_direct_symbol(const char *s, int *out, const char **label) {
    if (parse_direct(s, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && is_ident(s)) {
        *label = s;
        if (out) *out = 0;
        return true;
    }
    return false;
}

bool parse_bit_symbol(const char *s, int *out, const char **label) {
    if (!s || !*s) return false;
    static const char *bit_map[] = {
        "A.0", "ACC.0", "A.1", "ACC.1", "A.2", "ACC.2", "A.3", "ACC.3",
        "A.4", "ACC.4", "A.5", "ACC.5", "A.6", "ACC.6", "A.7", "ACC.7",
        "B.0", "B.1", "B.2", "B.3", "B.4", "B.5", "B.6", "B.7"
    };
    static const int bit_addr[] = {
        0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE2, 0xE3, 0xE3,
        0xE4, 0xE4, 0xE5, 0xE5, 0xE6, 0xE6, 0xE7, 0xE7,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7
    };
    for (int i = 0; i < sizeof(bit_map)/sizeof(bit_map[0]); ++i) {
        if (!strcmp(s, bit_map[i])) {
            if (out) *out = bit_addr[i];
            if (label) *label = NULL;
            return true;
        }
    }
    if (parse_int_val(s, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && is_ident(s)) {
        *label = s;
        if (out) *out = 0;
        return true;
    }
    return false;
}

bool parse_immediate_label(const char *s, int *out, const char **label) {
    if (!s || s[0] != '#') return false;
    if (parse_int_val(s + 1, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && is_ident(s + 1)) {
        *label = s + 1;
        if (out) *out = 0;
        return true;
    }
    return false;
}

SectionKind map_data_space(Ctype *type) {
    if (!type) return SEC_DATA;
    CtypeAttr a = get_attr(type->attr);
    switch (a.ctype_data) {
    case 1: return SEC_DATA;
    case 2: return SEC_IDATA;
    case 3: return SEC_PDATA;
    case 4: return SEC_XDATA;
    case 5: return SEC_XDATA;
    case 6: return SEC_CODE;
    default: return SEC_DATA;
    }
}

bool is_signed_type(Ctype *type) {
    return type && !get_attr(type->attr).ctype_unsigned;
}

bool is_register_mmio(Ctype *type) {
    return type && get_attr(type->attr).ctype_register != 0;
}

bool is_register_bit(Ctype *type) {
    return is_register_mmio(type) && type->type == CTYPE_BOOL;
}

int data_space_kind(Ctype *type) {
    if (!type) return 1;
    int d = get_attr(type->attr).ctype_data;
    return d ? d : 1;
}

bool func_stack_offset(Func *f, const char *name, int *out) {
    if (!f || !name || !f->stack_offsets) return false;
    int *p = (int *)dict_get(f->stack_offsets, (char *)name);
    if (!p) return false;
    if (out) *out = *p;
    return true;
}

/* === From c51_gen_section.c === */
Section *get_or_create_section(ObjFile *obj, const char *name, SectionKind kind) {
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        Section *sec = iter_next(&it);
        if (sec && sec->name && !strcmp(sec->name, name))
            return sec;
    }
    idx = objfile_add_section(obj, name, kind, 0, 1);
    return objfile_get_section(obj, idx);
}

int section_index_from_ptr(ObjFile *obj, Section *sec) {
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

void emit_global_data(ObjFile *obj, GlobalVar *g) {
    if (!g || !g->name) return;
    if (is_register_mmio(g->type)) {
        if (g->has_init) {
            bool is_bit = is_register_bit(g->type);
            mmio_map_put(g->name, (int)g->init_value, is_bit);
            unsigned flags = SYM_FLAG_GLOBAL | (is_bit ? SYM_FLAG_BIT : 0);
            objfile_add_symbol(obj, g->name, SYM_DATA, -2, (int)g->init_value, 1, flags);
        }
        return;
    }
    if (g->is_extern) {
        objfile_add_symbol(obj, g->name, SYM_DATA, -1, 0, g->type ? g->type->size : 0, SYM_FLAG_EXTERN);
        return;
    }

    SectionKind kind = map_data_space(g->type);
    const char *sec_name = ".data";
    if (kind == SEC_CODE) {
        sec_name = g->has_init ? ".const" : ".text";
    } else if (kind == SEC_XDATA) {
        sec_name = g->has_init ? ".xdata" : ".xdata_bss";
    } else if (kind == SEC_IDATA) {
        sec_name = g->has_init ? ".idata" : ".idata_bss";
    } else if (kind == SEC_PDATA) {
        sec_name = g->has_init ? ".pdata" : ".pdata_bss";
    } else {
        sec_name = g->has_init ? ".data" : ".bss";
    }
    Section *sec = get_or_create_section(obj, sec_name, kind);
    int offset = sec->bytes_len;
    int size = g->type ? g->type->size : 1;
    if (g->type) {
        switch (g->type->type) {
            case CTYPE_CHAR:
            case CTYPE_BOOL:
                size = 1;
                break;
            case CTYPE_INT:
                size = 2;
                break;
            case CTYPE_LONG:
                size = 4;
                break;
            case CTYPE_PTR:
                size = 2;
                break;
            case CTYPE_ARRAY:
            case CTYPE_STRUCT:
                size = g->type->size;
                break;
            default:
                break;
        }
    }

    if (g->init_instr && !list_empty(g->init_instr->labels)) {
        const char *label = (const char *)list_get(g->init_instr->labels, 0);
        if (size == 1) {
            emit_abs8(obj, sec, label);
        } else if (size == 2) {
            emit_abs16(obj, sec, label);
        } else if (size == 4) {
            emit_abs16(obj, sec, label);
            section_append_zeros(sec, 2);
        } else {
            section_append_zeros(sec, size);
        }
    } else if (g->init_instr && g->init_instr->imm.blob.bytes && g->init_instr->imm.blob.len > 0) {
        int copy_len = g->init_instr->imm.blob.len;
        if (copy_len > size) copy_len = size;
        section_append_bytes(sec, g->init_instr->imm.blob.bytes, copy_len);
        if (size > copy_len) section_append_zeros(sec, size - copy_len);
    } else if (g->has_init) {
        long v = g->init_value;
        if (size == 1) {
            unsigned char b = (unsigned char)(v & 0xFF);
            section_append_bytes(sec, &b, 1);
        } else if (size == 2) {
            unsigned char b[2] = {(unsigned char)(v & 0xFF), (unsigned char)((v >> 8) & 0xFF)};
            section_append_bytes(sec, b, 2);
        } else if (size == 4) {
            unsigned char b[4] = {
                (unsigned char)(v & 0xFF),
                (unsigned char)((v >> 8) & 0xFF),
                (unsigned char)((v >> 16) & 0xFF),
                (unsigned char)((v >> 24) & 0xFF)
            };
            section_append_bytes(sec, b, 4);
        } else {
            section_append_zeros(sec, size);
        }
    } else {
        section_append_zeros(sec, size);
    }

    unsigned flags = g->is_static ? SYM_FLAG_LOCAL : SYM_FLAG_GLOBAL;
    objfile_add_symbol(obj, g->name, SYM_DATA, section_index_from_ptr(obj, sec), offset, size, flags);
}

Symbol *find_symbol_by_name(ObjFile *obj, const char *name) {
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && name && !strcmp(sym->name, name))
            return sym;
    }
    return NULL;
}

void define_label_symbol(ObjFile *obj, const char *name, int section, int value) {
    if (!obj || !name) return;
    Symbol *sym = find_symbol_by_name(obj, name);
    if (!sym) {
        objfile_add_symbol(obj, name, SYM_LABEL, section, value, 0, SYM_FLAG_LOCAL);
        return;
    }
    sym->section = section;
    sym->value = value;
    sym->flags &= ~SYM_FLAG_EXTERN;
}

/* === From c51_gen_emit.c === */
char *g_pending_ssa = NULL;

void gen_set_pending_ssa(char *ssa) {
    free(g_pending_ssa);
    g_pending_ssa = ssa;
}

void gen_clear_pending_ssa(void) {
    free(g_pending_ssa);
    g_pending_ssa = NULL;
}

void gen_instr_copy_ssa(AsmInstr *dst, const AsmInstr *src) {
    if (!dst) return;
    free(dst->ssa);
    dst->ssa = NULL;
    if (src && src->ssa) {
        dst->ssa = gen_strdup(src->ssa);
    }
}

const char *vreg(ValueName v) {
    static char buf[4][32];
    static int idx = 0;
    idx = (idx + 1) % 4;
    snprintf(buf[idx], sizeof(buf[idx]), "v%d", v);
    return buf[idx];
}

AsmInstr *gen_instr_new(const char *op) {
    AsmInstr *ins = gen_alloc(sizeof(AsmInstr));
    ins->op = gen_strdup(op);
    ins->args = make_list();
    ins->ssa = NULL;
    return ins;
}

void gen_instr_add_arg(AsmInstr *ins, const char *arg) {
    if (!ins || !arg) return;
    list_push(ins->args, gen_strdup(arg));
}

void emit_ins0(Section *sec, const char *op) {
    AsmInstr *ins = gen_instr_new(op);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_ins1(Section *sec, const char *op, const char *a0) {
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_ins2(Section *sec, const char *op, const char *a0, const char *a1) {
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_ins3(Section *sec, const char *op, const char *a0, const char *a1, const char *a2) {
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    gen_instr_add_arg(ins, a2);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_label(Section *sec, const char *name) {
    if (!sec || !name) return;
    emit_ins1(sec, ".label", name);
}

void free_asminstr(AsmInstr *ins) {
    if (!ins) return;
    list_free(ins->args);
    free(ins->args);
    free(ins->op);
    free(ins->ssa);
    free(ins);
}

void emit_u8(Section *sec, unsigned char b) {
    section_append_bytes(sec, &b, 1);
}

void emit_u16(Section *sec, int v) {
    unsigned char b[2] = {(unsigned char)((v >> 8) & 0xFF), (unsigned char)(v & 0xFF)};
    section_append_bytes(sec, b, 2);
}

void emit_rel8(ObjFile *obj, Section *sec, const char *label) {
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u8(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_REL8, label, 0);
}

void emit_abs16(ObjFile *obj, Section *sec, const char *label) {
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u16(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_ABS16, label, 0);
}

void emit_abs8(ObjFile *obj, Section *sec, const char *label) {
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u8(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_ABS8, label, 0);
}

void emit_load_stack_param(Section *sec, int offset, const char *dst, bool use_fp) {
    if (!sec || !dst) return;
    char buf[16];
    emit_ins2(sec, "mov", "A", use_fp ? "0x2E" : "0x81");
    snprintf(buf, sizeof(buf), "#0x%02X", (unsigned char)(0 - offset));
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
    emit_ins2(sec, "mov", "A", "@r0");
    emit_ins2(sec, "mov", dst, "A");
}

void emit_load_stack_param_to_direct(Section *sec, int offset, int addr, bool use_fp) {
    if (!sec) return;
    char buf[16];
    char dst[16];
    emit_ins2(sec, "mov", "A", use_fp ? "0x2E" : "0x81");
    snprintf(buf, sizeof(buf), "#0x%02X", (unsigned char)(0 - offset));
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
    emit_ins2(sec, "mov", "A", "@r0");
    fmt_direct(dst, sizeof(dst), addr);
    emit_ins2(sec, "mov", dst, "A");
}

void emit_stack_addr(Section *sec, int offset) {
    char buf[16];
    emit_ins2(sec, "mov", "A", "0x2E");
    snprintf(buf, sizeof(buf), "#%d", offset + 1);
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
}

void emit_frame_prologue(Section *sec, int stack_size) {
    if (!sec || stack_size <= 0) return;
    char buf[16];
    emit_ins2(sec, "mov", "0x2E", "0x81");
    emit_ins2(sec, "mov", "A", "0x81");
    snprintf(buf, sizeof(buf), "#%d", stack_size);
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "0x81", "A");
}

void emit_frame_epilogue(Section *sec, int stack_size) {
    if (!sec || stack_size <= 0) return;
    emit_ins2(sec, "mov", "0x81", "0x2E");
}

void emit_interrupt_prologue(Section *sec) {
    if (!sec) return;
    emit_ins1(sec, "push", "A");
    emit_ins1(sec, "push", "0xD0");
    emit_ins1(sec, "push", "0x82");
    emit_ins1(sec, "push", "0x83");
}

void emit_interrupt_epilogue(Section *sec) {
    if (!sec) return;
    emit_ins1(sec, "pop", "0x83");
    emit_ins1(sec, "pop", "0x82");
    emit_ins1(sec, "pop", "0xD0");
    emit_ins1(sec, "pop", "A");
}

char *new_label(const char *prefix) {
    char buf[64];
    snprintf(buf, sizeof(buf), "L%s_%d", prefix, g_lower_id++);
    return gen_strdup(buf);
}

const char *map_block_label(const char *func_name, const char *label) {
    if (!label) return "<null>";
    int id = -1;
    if (strncmp(label, "block", 5) == 0) {
        id = atoi(label + 5);
    } else if (label[0] == 'b' && isdigit((unsigned char)label[1])) {
        id = atoi(label + 1);
    }
    if (id >= 0) {
        static char buf[96];
        snprintf(buf, sizeof(buf), "L%s_%d", func_name ? func_name : "fn", id);
        return buf;
    }
    return label;
}

int param_index(Func *f, const char *name) {
    if (!f || !f->params || !name) return -1;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        if (p && !strcmp(p, name)) return idx;
    }
    return -1;
}

Ctype *param_type(Func *f, const char *name) {
    if (!f || !f->params || !f->param_types || !name) return NULL;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        if (p && !strcmp(p, name)) {
            return (Ctype *)list_get(f->param_types, idx);
        }
    }
    return NULL;
}

int param_byte_offset(Func *f, const char *name, Ctype **out_type) {
    if (!f || !f->params || !name) return -1;
    int offset = 0;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        Ctype *t = (f->param_types && idx < f->param_types->len) ? (Ctype *)list_get(f->param_types, idx) : NULL;
        int sz = t ? t->size : 1;
        if (p && !strcmp(p, name)) {
            if (out_type) *out_type = t;
            return offset;
        }
        offset += (sz >= 2) ? 2 : 1;
    }
    return -1;
}

Block *find_block_by_label(Func *f, const char *label) {
    if (!f || !label) return NULL;
    int id = -1;
    if (strncmp(label, "block", 5) == 0) {
        id = atoi(label + 5);
    } else if (label[0] == 'b' && isdigit((unsigned char)label[1])) {
        id = atoi(label + 1);
    }
    if (id < 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (b && (int)b->id == id) return b;
    }
    return NULL;
}

const char *find_var_for_value(Block *blk, ValueName v) {
    if (!blk || !blk->var_map || v == 0) return NULL;
    for (Iter it = list_iter(blk->var_map->list); !iter_end(it);) {
        DictEntry *e = iter_next(&it);
        if (!e || !e->val) continue;
        ValueName *val = (ValueName *)e->val;
        if (*val == v) return e->key;
    }
    return NULL;
}

bool value_defined_in_block(Block *blk, ValueName v) {
    if (!blk || v == 0) return false;
    for (Iter it = list_iter(blk->instrs); !iter_end(it);) {
        Instr *ins = iter_next(&it);
        if (ins && ins->dest == v && ins->op != IROP_NOP && ins->op != IROP_PHI)
            return true;
    }
    return false;
}

#ifdef MINITEST_IMPLEMENTATION
#include "../minitest.h"

static ObjFile *compile_one(const char *path) {
    freopen(path, "r", stdin);
    set_current_filename(path);

    SSABuild *b = ssa_build_create();
    List *tops = read_toplevels();
    for (Iter i = list_iter(tops); !iter_end(i);) {
        Ast *t = iter_next(&i);
        printf("ast: %s\n", ast_to_string(t));
        ssa_convert_ast(b, t);
    }
        
    ssa_optimize(b->unit, OPT_O1);
    ssa_print(stdout, b->unit);
    ObjFile *o = c51_gen_from_ssa(b->unit);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
    return o;
}

TEST(test, c51_gen) {
    char f[256];
    fgets(f, sizeof f, stdin);
    *strchr(f, '\n') = 0;
    c51_write_asm(stdout, compile_one(f));
}

TEST(test, c51_link) {
    char f[256];
    List *o = make_list();
    while (fgets(f, sizeof f, stdin)) {
        *strchr(f, '\n') = 0;
        if (!*f) break;
        list_push(o, compile_one(f));
    }

    ObjFile *out = obj_link(o);
    c51_write_asm(stdout, out);
    c51_write_hex(stdout, out);
}
#endif