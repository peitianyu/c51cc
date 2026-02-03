#include "c51_gen.h"

extern ObjFile *c51_link(List *objs);

/* === Entry point === */
ObjFile *c51_gen_from_ssa(void *ssa)
{
    SSAUnit *unit = (SSAUnit *)ssa;
    if (!unit) return NULL;

    ObjFile *obj = objfile_new();

    g_mmio_map = make_dict(NULL);

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        emit_global_data(obj, g);
    }

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (!f || !f->name) continue;
        g_addr_map = make_dict(NULL);
        g_const_map = make_dict(NULL);
        g_val_type = make_dict(NULL);
        g_v16_map = make_dict(NULL);
        g_v16_next = 0x70;
        char sec_name[128];
        snprintf(sec_name, sizeof(sec_name), ".text.%s", f->name);
        Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

        objfile_add_symbol(obj, (char *)f->name, SYM_FUNC, section_index_from_ptr(obj, sec), 0, 0, SYM_FLAG_GLOBAL);
        emit_label(sec, f->name);
        if (f->is_interrupt) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%d", f->interrupt_id);
            emit_ins1(sec, ".interrupt", buf);
            if (f->bank_id >= 0) {
                char bbuf[16];
                snprintf(bbuf, sizeof(bbuf), "%d", f->bank_id);
                emit_ins1(sec, ".using", bbuf);
            }
            emit_interrupt_prologue(sec);
        }
        if (f->stack_size > 0)
            emit_frame_prologue(sec, f->stack_size);

        for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
            Block *b = iter_next(&bit);
            if (!b) continue;
            char label[64];
            snprintf(label, sizeof(label), "L%s_%u", f->name, b->id);
            emit_label(sec, label);

            for (Iter it = list_iter(b->instrs); !iter_end(it);) {
                Instr *ins = iter_next(&it);
                emit_instr(sec, ins, f, b);
            }
        }

        regalloc_section_asminstrs(sec);
        lower_section_asminstrs(sec);
        shrink_call_saves(sec);
        peephole_section_asminstrs(sec);
        fixup_short_jumps(sec);
        encode_section_bytes(obj, sec);

        if (g_addr_map) {
            for (Iter it = list_iter(g_addr_map->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
                free(e->val);
            }
            dict_clear(g_addr_map);
            g_addr_map = NULL;
        }
        if (g_const_map) {
            for (Iter it = list_iter(g_const_map->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
                free(e->val);
            }
            dict_clear(g_const_map);
            g_const_map = NULL;
        }
        if (g_val_type) {
            for (Iter it = list_iter(g_val_type->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
            }
            dict_clear(g_val_type);
            g_val_type = NULL;
        }
        if (g_v16_map) {
            for (Iter it = list_iter(g_v16_map->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
                free(e->val);
            }
            dict_clear(g_v16_map);
            g_v16_map = NULL;
        }
    }

    if (g_mmio_map) {
        for (Iter it = list_iter(g_mmio_map->list); !iter_end(it);) {
            DictEntry *e = iter_next(&it);
            if (!e) continue;
            free(e->key);
            free(e->val);
        }
        dict_clear(g_mmio_map);
        g_mmio_map = NULL;
    }

    /* 顶层 asm 块：汇编后与当前 ObjFile 合并（走 linker 的 section/symbol/reloc 合并逻辑） */
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
                fprintf(stderr, "asm block assemble failed at line %d: %s\n", err_line, err ? err : "(null)");
                if (err) free(err);
                exit(1);
            }
            if (err) free(err);

            for (Iter sit = list_iter(aobj->sections); !iter_end(sit);) {
                Section *sec = iter_next(&sit);
                if (!sec) continue;
                encode_section_bytes(aobj, sec);
            }

            list_push(objs, aobj);
        }

        ObjFile *out = c51_link(objs);

        /* 输入 objs 的生命周期到此结束 */
        for (Iter oit = list_iter(objs); !iter_end(oit);) {
            ObjFile *in = iter_next(&oit);
            if (in) objfile_free(in);
        }

        /* list_free 会 free(elem)，这里已经 objfile_free 过了，先清空 elem 避免 double free */
        for (ListNode *n = objs->head; n; n = n->next) n->elem = NULL;
        list_free(objs);
        free(objs);

        return out;
    }

    return obj;
}

#ifdef MINITEST_IMPLEMENTATION
#include "../minitest.h"

TEST(test, c51_gen) {
    char infile[256];
    printf("file path for C51 gen test: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    /* 避免下一行 asm 输出粘连在提示后面 */
    fflush(stdout);
    putchar('\n');

    set_current_filename(infile);

    SSABuild *b = ssa_build_create();
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("ast %s\n", ast_to_string(v));
        ssa_convert_ast(b, v);
    }

    ssa_optimize(b->unit, OPT_O1);

    ObjFile *obj = c51_gen_from_ssa(b->unit);
    Section *code_sec = NULL;
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) { code_sec = sec; break; }
    }
    if (code_sec && code_sec->asminstrs) {
        for (Iter it = list_iter(code_sec->asminstrs); !iter_end(it);)
            (void)iter_next(&it);
    }
    c51_write_asm(stdout, obj);

    objfile_free(obj);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif
