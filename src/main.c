#ifdef MINITEST_IMPLEMENTATION
#define MINITEST_MAIN  /* Windows: 在此定义 __t_begin 和全局存储 */
#include "core/minitest.h"

int g_argc;
char **g_argv;
int main(int argc, char **argv) {
    RUN_ALL_TESTS(argc, argv);
    return 0;
}

#else 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cc.h"
#include "core/ssa.h"
#include "core/c51/c51_gen.h"

/* ---------------------------------------------------------------
 * 用法:
 *   c51cc [options] <input.c>
 *
 * options:
 *   -ast        仅输出 AST（解析后，不做 SSA/代码生成）
 *   -ssa        输出 SSA IR（优化前后）
 *   -asm        输出汇编（8051 助记符）
 *   -hex        输出 Intel HEX
 *   -O0/-O1/-O2 优化级别（默认 O1）
 *   -o <file>   输出到文件（默认 stdout）
 *
 * 若不带任何 flag，则默认等价于 -asm 输出。
 * --------------------------------------------------------------- */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <input.c>\n"
        "Options:\n"
        "  -ast         Print AST\n"
        "  -ssa         Print SSA IR\n"
        "  -asm         Emit 8051 assembly (default)\n"
        "  -hex         Emit Intel HEX\n"
        "  -O0/-O1/-O2  Optimization level (default: O1)\n"
        "  -o <file>    Output file (default: stdout)\n"
        "               With -asm and -hex together, writes sibling .asm/.hex files\n"
        "  -I<path>     Add include search path\n",
        prog ? prog : "c51cc"
    );
}

static char *replace_extension(const char *path, const char *ext)
{
    const char *slash;
    const char *dot;
    size_t base_len;
    size_t ext_len;
    char *out;

    if (!path || !ext) return NULL;
    slash = strrchr(path, '/');
    if (!slash) slash = strrchr(path, '\\');
    dot = strrchr(path, '.');
    if (!dot || (slash && dot < slash)) dot = path + strlen(path);

    base_len = (size_t)(dot - path);
    ext_len = strlen(ext);
    out = calloc(base_len + ext_len + 1, 1);
    if (!out) return NULL;
    memcpy(out, path, base_len);
    memcpy(out + base_len, ext, ext_len);
    out[base_len + ext_len] = '\0';
    return out;
}

int main(int argc, char **argv) {
    int opt_ast = 0;
    int opt_ssa = 0;
    int opt_asm = 0;
    int opt_hex = 0;
    int opt_level = OPT_O1;
    const char *input_file = NULL;
    const char *output_file = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-ast") == 0) {
            opt_ast = 1;
        } else if (strcmp(a, "-ssa") == 0) {
            opt_ssa = 1;
        } else if (strcmp(a, "-asm") == 0) {
            opt_asm = 1;
        } else if (strcmp(a, "-hex") == 0) {
            opt_hex = 1;
        } else if (strcmp(a, "-O0") == 0) {
            opt_level = OPT_O0;
        } else if (strcmp(a, "-O1") == 0) {
            opt_level = OPT_O1;
        } else if (strcmp(a, "-O2") == 0) {
            opt_level = OPT_O2;
        } else if (strcmp(a, "-o") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                fprintf(stderr, "error: -o requires an argument\n");
                return 1;
            }
        } else if (a[0] == '-' && a[1] == 'I') {
            /* -Ipath 或 -I path 两种形式 */
            const char *ipath = (a[2] != '\0') ? a + 2 : (i + 1 < argc ? argv[++i] : NULL);
            if (!ipath) {
                fprintf(stderr, "error: -I requires an argument\n");
                return 1;
            }
            pp_global_add_include_path(ipath);
        } else if (a[0] == '-') {
            fprintf(stderr, "error: unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        } else {
            /* Collect input files (support multiple translation units) */
            if (!input_file) {
                /* use input_file to store first path for backward compatibility */
                input_file = a;
            }
            /* push path to a simple list via argv reuse: we'll handle multiple files later */
            /* For simplicity, store additional files into argv by moving index forward */
            /* We'll parse all non-option args from argv[1..argc-1] below */
            /* Nothing to do here now */
            /* Keep last non-option in input_file for startup lookup */
            input_file = input_file; /* no-op to silence possible warnings */
            /* Append processing will be done after argument parsing */
            /* To mark presence of multiple files we just continue */
        }
    }

    /* 没有输入文件 */
    if (!input_file) {
        usage(argv[0]);
        return 1;
    }

    /* Collect all non-option arguments as input files (preserve order) */
    List *input_paths = make_list();
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-') {
            if (a[1] == 'I') {
                /* -I handled earlier; skip possible separate arg */
                if (a[2] == '\0') i++; /* skip next arg used by -I */
            } else if (strcmp(a, "-o") == 0) {
                i++; /* skip output file arg */
            }
            continue;
        }
        list_push(input_paths, strdup(a));
    }
    if (list_empty(input_paths)) {
        usage(argv[0]);
        return 1;
    }

    /* 若没有指定任何输出模式，默认 -asm */
    if (!opt_ast && !opt_ssa && !opt_asm && !opt_hex) {
        opt_asm = 1;
    }

    FILE *out_fp = stdout;
    FILE *asm_fp = stdout;
    FILE *hex_fp = stdout;
    char *asm_path = NULL;
    char *hex_path = NULL;

    if (output_file && opt_asm && opt_hex) {
        asm_path = replace_extension(output_file, ".asm");
        hex_path = replace_extension(output_file, ".hex");
        if (!asm_path || !hex_path) {
            free(asm_path);
            free(hex_path);
            fprintf(stderr, "error: cannot allocate output paths\n");
            return 1;
        }
        asm_fp = c51cc_fopen(asm_path, "w");
        hex_fp = c51cc_fopen(hex_path, "w");
        if (!asm_fp || !hex_fp) {
            if (asm_fp && asm_fp != stdout) fclose(asm_fp);
            if (hex_fp && hex_fp != stdout) fclose(hex_fp);
            fprintf(stderr, "error: cannot open output files: %s / %s\n", asm_path, hex_path);
            free(asm_path);
            free(hex_path);
            return 1;
        }
        out_fp = asm_fp;
    } else if (output_file) {
        out_fp = c51cc_fopen(output_file, "w");
        if (!out_fp) {
            fprintf(stderr, "error: cannot open output file: %s\n", output_file);
            return 1;
        }
        asm_fp = out_fp;
        hex_fp = out_fp;
    }

    /* ---- 支持多文件编译/链接 ---- */
    List *objs = make_list();
    const char *first_input = NULL;

    for (Iter it = list_iter(input_paths); !iter_end(it);) {
        char *path = iter_next(&it);
        if (!path) continue;
        if (!first_input) first_input = path;

        /* 1. 预处理 */
        if (!pp_preprocess_to_stdin(path)) {
            fprintf(stderr, "error: preprocess failed: %s\n", path);
            goto fail_cleanup;
        }
        set_current_filename(path);

        /* 2. 解析 AST */
        parser_reset();
        List *toplevels = read_toplevels();
        if (!toplevels) {
            fprintf(stderr, "error: parse failed: %s\n", path);
            goto fail_cleanup;
        }

        /* 3. 构建 SSA */
        SSABuild *b = ssa_build_create();
        if (!b) {
            fprintf(stderr, "error: ssa_build_create failed\n");
            goto fail_cleanup;
        }
        for (Iter i = list_iter(toplevels); !iter_end(i);) {
            Ast *v = iter_next(&i);
            if (v) ast_to_ssa(b, v);
        }
        /* 优化 */
        ssa_optimize(b->unit, opt_level);

        /* 4. 代码生成 */
        ObjFile *o = c51_gen(b->unit);
        ssa_build_destroy(b);
        list_free(strings);
        list_free(ctypes);

        if (!o) {
            fprintf(stderr, "error: code generation failed: %s\n", path);
            goto fail_cleanup;
        }
        list_push(objs, o);
    }

    /* 如果只有一个输入文件，直接使用 objs[0] ，否则链接所有 objs */
    ObjFile *out = NULL;
    if (list_len(objs) == 1) {
        out = list_get(objs, 0);
    } else {
        /* 标记非第一个输入文件中的 main 为 extern，避免重复定义 */
        Iter pit = list_iter(input_paths);
        Iter oit = list_iter(objs);
        /* first_input 已是第一个路径 */
        /* Advance both iterators and for any path not equal to first_input,
           set its 'main' symbol to undefined (section = -1) if present. */
        while (!iter_end(pit) && !iter_end(oit)) {
            char *pp = iter_next(&pit);
            ObjFile *oo = iter_next(&oit);
            if (!pp || !oo) continue;
            if (strcmp(pp, first_input) == 0) continue;
            /* Scan symbols and mark 'main' as extern */
            for (Iter sit = list_iter(oo->symbols); !iter_end(sit);) {
                Symbol *s = iter_next(&sit);
                if (!s || !s->name) continue;
                if (strcmp(s->name, "main") == 0) {
                    s->section = -1;
                    s->flags |= SYM_FLAG_EXTERN;
                }
            }
                /* Also remove the assembly block for _main from sections (labels + body) */
                for (Iter secit = list_iter(oo->sections); !iter_end(secit);) {
                    Section *sec = iter_next(&secit);
                    if (!sec || !sec->asminstrs) continue;
                    List *new_list = make_list();
                    bool skip = false;
                    for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                        AsmInstr *ain = iter_next(&ait);
                        if (!ain) continue;
                        if (!skip) {
                            if (ain->op && strcmp(ain->op, "_main:") == 0) {
                                /* start skipping this function */
                                skip = true;
                                /* free this label instruction */
                                if (ain->args) { list_free(ain->args); free(ain->args); }
                                if (ain->ssa) free(ain->ssa);
                                free(ain->op);
                                free(ain);
                                continue;
                            } else {
                                /* keep instruction */
                                list_push(new_list, ain);
                            }
                        } else {
                            /* currently skipping until next label */
                            size_t oplen = ain->op ? strlen(ain->op) : 0;
                            bool is_label = (oplen > 0 && ain->op[oplen - 1] == ':');
                            if (is_label) {
                                /* stop skipping and keep this label */
                                skip = false;
                                list_push(new_list, ain);
                            } else {
                                /* free this instruction */
                                if (ain->args) { list_free(ain->args); free(ain->args); }
                                if (ain->ssa) free(ain->ssa);
                                if (ain->op) free(ain->op);
                                free(ain);
                            }
                        }
                    }
                    /* replace asminstrs list */
                    /* free old list node containers without freeing elem pointers (they were moved or freed above) */
                    if (sec->asminstrs) {
                        struct __ListNode *node = ((List *)sec->asminstrs)->head;
                        while (node) {
                            struct __ListNode *nxt = node->next;
                            free(node);
                            node = nxt;
                        }
                        free(sec->asminstrs);
                    }
                    sec->asminstrs = new_list;
                }
        }

        out = obj_link(objs);
        if (!out) {
            fprintf(stderr, "error: linking objects failed\n");
            goto fail_cleanup;
        }
        /* 释放原始对象列表（obj_link 不会释放输入对象） */
        for (Iter it2 = list_iter(objs); !iter_end(it2);) {
            ObjFile *o = iter_next(&it2);
            if (o) obj_free(o);
        }
    }

    /* 注入 startup / runtime */
    ObjFile *linked_obj = c51_link_startup(first_input, out);
    if (linked_obj && linked_obj != out) {
        obj_free(out);
        out = linked_obj;
    }

    /* 输出 */
    if (opt_asm) c51_write_asm(asm_fp, out);
    if (opt_hex) c51_write_hex(hex_fp, out);

    if (out) obj_free(out);
    if (asm_fp != stdout) fclose(asm_fp);
    if (hex_fp != stdout && hex_fp != asm_fp) fclose(hex_fp);
    free(asm_path);
    free(hex_path);

    /* 释放 input_paths 列表内存 */
    for (Iter it3 = list_iter(input_paths); !iter_end(it3);) free(iter_next(&it3));
    free(input_paths);
    free(objs);
    return 0;

fail_cleanup:
    /* 清理 on error */
    for (Iter it4 = list_iter(objs); !iter_end(it4);) {
        ObjFile *o = iter_next(&it4);
        if (o) obj_free(o);
    }
    for (Iter it5 = list_iter(input_paths); !iter_end(it5);) free(iter_next(&it5));
    free(input_paths);
    free(objs);
    if (asm_fp != stdout) fclose(asm_fp);
    if (hex_fp != stdout && hex_fp != asm_fp) fclose(hex_fp);
    free(asm_path);
    free(hex_path);
    return 1;
}

#endif /* MINITEST_IMPLEMENTATION */