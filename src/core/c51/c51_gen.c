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
        g_v16_next = 0x70;

        char sec_name[128];
        snprintf(sec_name, sizeof sec_name, ".text.%s", f->name);
        Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

        objfile_add_symbol(obj, (char *)f->name, SYM_FUNC,
                          section_index_from_ptr(obj, sec),
                          0, 0, SYM_FLAG_GLOBAL);
        emit_label(sec, f->name);

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
        for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
            Block *b = iter_next(&bit);
            if (!b) continue;
            char label[64];
            snprintf(label, sizeof label, "L%s_%u", f->name, b->id);
            emit_label(sec, label);
            for (Iter it = list_iter(b->instrs); !iter_end(it);)
                emit_instr(sec, iter_next(&it), f, b);
        }

        /* 后端流水线 */
        regalloc_section_asminstrs(sec);
        lower_section_asminstrs(sec);
        shrink_call_saves(sec);
        peephole_section_asminstrs(sec);
        fixup_short_jumps(sec);
        encode_section_bytes(obj, sec);

        /* 函数级字典统一释放 */
        dict_free_kv(g_addr_map);  g_addr_map = NULL;
        dict_free_kv(g_const_map); g_const_map = NULL;
        dict_free_kv(g_v16_map);   g_v16_map   = NULL;
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

        /* 清理输入对象列表（已深 free）*/
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
    for (Iter i = list_iter(tops); !iter_end(i);)
        ssa_convert_ast(b, iter_next(&i));
    ssa_optimize(b->unit, OPT_O1);
    // ssa_print(stdout, b->unit);
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
