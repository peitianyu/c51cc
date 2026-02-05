#include "c51_gen.h"

static void dict_free_kv(Dict *d)
{
    if (!d) return;
    for (Iter it = list_iter(d->list); !iter_end(it);) {
        DictEntry *e = iter_next(&it);
        if (e) { free(e->key); free(e->val); }
    }
    dict_clear(d);
}

static bool instr_has_imm_tag(const Instr *ins, int *out)
{
    if (!ins || !ins->labels || ins->labels->len < 1) return false;
    char *tag = (char *)list_get(ins->labels, 0);
    if (tag && strcmp(tag, "imm") == 0) {
        if (out) *out = (int)ins->imm.ival;
        return true;
    }
    return false;
}

static bool func_has_call(Func *f)
{
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

static bool v16_reg_mapped(ValueName v)
{
    if (!g_v16_reg_map || v <= 0) return false;
    return dict_get(g_v16_reg_map, vreg_key(v)) != NULL;
}

static Instr *find_def_instr_in_block(Block *b, ValueName v);

static Instr *find_def_instr_in_func(Func *f, ValueName v)
{
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

static bool is_v16_candidate(Func *f, ValueName v)
{
    Instr *def = find_def_instr_in_func(f, v);
    if (def && def->type && def->type->size >= 2) return true;
    if (!f || v == 0) return false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || !i->args) continue;
            bool uses = false;
            for (int k = 0; k < i->args->len; ++k) {
                ValueName *arg = list_get(i->args, k);
                if (arg && *arg == v) { uses = true; break; }
            }
            if (uses && i->type && i->type->size >= 2) return true;
        }
    }
    return false;
}

static void select_v16_reg_pairs(Func *f)
{
    if (!f || !g_v16_reg_map) return;
    if (func_has_call(f)) return;

    int pairs[2][2] = { {6, 7}, {4, 5} };
    int picked = 0;

    for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
        Block *b = iter_next(&bit);
        if (!b || !b->phis) continue;
        for (Iter pit = list_iter(b->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (!phi || phi->op != IROP_PHI) continue;
            if (!is_v16_candidate(f, phi->dest)) continue;
            if (v16_reg_mapped(phi->dest)) continue;

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
                int imm = 0;
                bool imm_is_one = instr_has_imm_tag(def, &imm) && imm == 1;
                if (!imm_is_one && def->args) {
                    for (int k = 0; k < def->args->len; ++k) {
                        ValueName *av = list_get(def->args, k);
                        if (!av || *av == phi->dest) continue;
                        Instr *cdef = find_def_instr_in_func(f, *av);
                        if (cdef && cdef->op == IROP_CONST && cdef->imm.ival == 1) {
                            imm_is_one = true;
                            break;
                        }
                    }
                }
                if (!imm_is_one) continue;
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

static int count_value_uses_func(Func *f, ValueName v)
{
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

static Instr *find_def_instr_in_block(Block *b, ValueName v)
{
    if (!b || v == 0 || !b->instrs) return NULL;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (i && i->dest == v) return i;
    }
    return NULL;
}

static void prepare_phi_aliases(Func *f, Block *from)
{
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

            if (src_val == 0 || src_val == phi->dest) continue;
            if (count_value_uses_func(f, src_val) > 1) continue;
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

/* ---------- 主入口 ---------- */
ObjFile *c51_gen_from_ssa(void *ssa)
{
    SSAUnit *unit = (SSAUnit *)ssa;
    if (!unit) return NULL;

    ObjFile *obj = objfile_new();
    g_mmio_map = make_dict(NULL);

    /* 1. 生成全局变量 */
    for (Iter git = list_iter(unit->globals); !iter_end(git);)
        emit_global_data(obj, iter_next(&git));

    /* 2. 逐个函数 */
    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (!f || !f->name) continue;

        /* 每函数级上下文 */
        g_addr_map = make_dict(NULL);
        g_const_map = make_dict(NULL);
        g_val_type = make_dict(NULL);
        g_v16_map = make_dict(NULL);
        g_v16_reg_map = make_dict(NULL);
        g_v16_alias = make_dict(NULL);
        g_v16_next = 0;
        if (g_v16_base_label) { free(g_v16_base_label); g_v16_base_label = NULL; }
        char v16_label[128];
        snprintf(v16_label, sizeof v16_label, "__v16_%s", f->name);
        g_v16_base_label = gen_strdup(v16_label);

        select_v16_reg_pairs(f);

        char sec_name[128];
        snprintf(sec_name, sizeof sec_name, ".text.%s", f->name);
        Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

        objfile_add_symbol(obj, (char *)f->name, SYM_FUNC,
                          section_index_from_ptr(obj, sec),
                          0, 0, SYM_FLAG_GLOBAL);
        emit_label(sec, f->name);

        if (!f->is_interrupt) {
            char ubuf[8];
            int bank = (f->bank_id >= 0) ? f->bank_id : 0;
            snprintf(ubuf, sizeof ubuf, "%d", bank);
            emit_ins1(sec, ".using", ubuf);
        }

        /* 中断函数特殊处理 */
        if (f->is_interrupt) {
            char buf[16], bbuf[16];
            snprintf(buf, sizeof buf, "%d", f->interrupt_id);
            emit_ins1(sec, ".interrupt", buf);
            if (f->bank_id >= 0) {
                snprintf(bbuf, sizeof bbuf, "%d", f->bank_id);
                emit_ins1(sec, ".using", bbuf);
            }
            emit_interrupt_prologue(sec);
        }
        if (f->stack_size > 0)
            emit_frame_prologue(sec, f->stack_size);

        /* 基本块 */
        Block *last_block = NULL;
        for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
            Block *b = iter_next(&bit);
            if (!b) continue;
            last_block = b;
            char label[64];
            snprintf(label, sizeof label, "L%s_%u", f->name, b->id);
            emit_label(sec, label);
            prepare_phi_aliases(f, b);
            for (Iter it = list_iter(b->instrs); !iter_end(it);)
                emit_instr(sec, iter_next(&it), f, b);
        }
        
        /* 如果函数没有显式返回，添加 ret */
        if (last_block) {
            bool has_ret = false;
            for (Iter it = list_iter(last_block->instrs); !iter_end(it);) {
                Instr *ins = iter_next(&it);
                if (ins && ins->op == IROP_RET) {
                    has_ret = true;
                    break;
                }
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

        /* 后端流水线 */
        regalloc_section_asminstrs(sec);
        lower_section_asminstrs(sec);
        shrink_call_saves(sec);
        peephole_section_asminstrs(sec);
        remove_unused_labels(sec);
        fixup_short_jumps(sec);
        encode_section_bytes(obj, sec);

        if (g_v16_next > 0 && g_v16_base_label) {
            char v16_sec[128];
            snprintf(v16_sec, sizeof v16_sec, ".data.v16.%s", f->name);
            Section *dsec = get_or_create_section(obj, v16_sec, SEC_DATA);
            int offset = dsec->bytes_len;
            section_append_zeros(dsec, g_v16_next);
            objfile_add_symbol(obj, g_v16_base_label, SYM_DATA,
                              section_index_from_ptr(obj, dsec),
                              offset, g_v16_next, SYM_FLAG_LOCAL);
        }

        /* 函数级字典统一释放 */
        dict_free_kv(g_addr_map);  g_addr_map = NULL;
        dict_free_kv(g_const_map); g_const_map = NULL;
        dict_free_kv(g_v16_map);   g_v16_map   = NULL;
        dict_free_kv(g_v16_reg_map); g_v16_reg_map = NULL;
        dict_free_kv(g_v16_alias); g_v16_alias = NULL;
        if (g_v16_base_label) { free(g_v16_base_label); g_v16_base_label = NULL; }
        if (g_val_type) {           /* 只释放 key */
            for (Iter it = list_iter(g_val_type->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (e) free(e->key);
            }
            dict_clear(g_val_type);
            g_val_type = NULL;
        }
    }

    /* 3. 模块级 MMIO 字典 */
    dict_free_kv(g_mmio_map);
    g_mmio_map = NULL;

    /* 4. 合并顶层 asm 块（若有） */
    if (unit->asm_blocks && unit->asm_blocks->len > 0) {
        List *objs = make_list();
        list_push(objs, obj);

        for (Iter it = list_iter(unit->asm_blocks); !iter_end(it);) {
            char *text = iter_next(&it);
            if (!text || !*text) continue;

            char *err = NULL;
            int err_line = 0;
            ObjFile *aobj = c51_asm_from_text(text, &err, &err_line);
            if (!aobj) {
                fprintf(stderr, "asm block assemble failed at line %d: %s\n",
                        err_line, err ? err : "(null)");
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
        list_free(objs); free(objs);

        return out;
    }

    return obj;
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
