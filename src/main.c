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
        "  -o <file>    Output file (default: stdout)\n",
        prog ? prog : "c51cc"
    );
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
        } else if (a[0] == '-') {
            fprintf(stderr, "error: unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        } else {
            if (input_file) {
                fprintf(stderr, "error: multiple input files not supported\n");
                return 1;
            }
            input_file = a;
        }
    }

    /* 没有输入文件 */
    if (!input_file) {
        usage(argv[0]);
        return 1;
    }

    /* 若没有指定任何输出模式，默认 -asm */
    if (!opt_ast && !opt_ssa && !opt_asm && !opt_hex) {
        opt_asm = 1;
    }

    /* 打开输出文件 */
    FILE *out_fp = stdout;
    if (output_file) {
        out_fp = fopen(output_file, "w");
        if (!out_fp) {
            fprintf(stderr, "error: cannot open output file: %s\n", output_file);
            return 1;
        }
    }

    /* ---- 1. 预处理 ---- */
    if (!pp_preprocess_to_stdin(input_file)) {
        fprintf(stderr, "error: preprocess failed: %s\n", input_file);
        if (out_fp != stdout) fclose(out_fp);
        return 1;
    }
    set_current_filename(input_file);

    /* ---- 2. 解析 AST ---- */
    parser_reset();
    List *toplevels = read_toplevels();
    if (!toplevels) {
        fprintf(stderr, "error: parse failed\n");
        if (out_fp != stdout) fclose(out_fp);
        return 1;
    }

    /* ---- 3. 输出 AST（若需要）---- */
    if (opt_ast) {
        fprintf(out_fp, "; ==== AST ====\n");
        for (Iter i = list_iter(toplevels); !iter_end(i);) {
            Ast *v = iter_next(&i);
            if (v) fprintf(out_fp, "%s\n", ast_to_string(v));
        }
        /* AST 模式不需要继续往后走 */
        if (!opt_ssa && !opt_asm && !opt_hex) {
            list_free(strings);
            list_free(ctypes);
            if (out_fp != stdout) fclose(out_fp);
            return 0;
        }
    }

    /* ---- 4. 构建 SSA ---- */
    SSABuild *b = ssa_build_create();
    if (!b) {
        fprintf(stderr, "error: ssa_build_create failed\n");
        if (out_fp != stdout) fclose(out_fp);
        return 1;
    }

    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        if (v) ast_to_ssa(b, v);
    }

    /* ---- 5. 输出 SSA（优化前，若需要）---- */
    if (opt_ssa) {
        fprintf(out_fp, "; ==== SSA (before opt) ====\n");
        ssa_print(out_fp, b->unit);
    }

    /* ---- 6. SSA 优化 ---- */
    ssa_optimize(b->unit, opt_level);

    /* ---- 7. 输出优化后 SSA（若需要）---- */
    if (opt_ssa) {
        fprintf(out_fp, "; ==== SSA (after opt O%d) ====\n", opt_level);
        ssa_print(out_fp, b->unit);
        /* SSA 模式若不需要生成代码则退出 */
        if (!opt_asm && !opt_hex) {
            ssa_build_destroy(b);
            list_free(strings);
            list_free(ctypes);
            if (out_fp != stdout) fclose(out_fp);
            return 0;
        }
    }

    /* ---- 8. 代码生成 ---- */
    ObjFile *obj = c51_gen(b->unit);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);

    if (!obj) {
        fprintf(stderr, "error: code generation failed\n");
        if (out_fp != stdout) fclose(out_fp);
        return 1;
    }

    ObjFile *linked_obj = c51_link_startup(input_file, obj);
    if (linked_obj && linked_obj != obj) {
        obj_free(obj);
        obj = linked_obj;
    }

    /* ---- 9. 输出汇编 ---- */
    if (opt_asm) {
        c51_write_asm(out_fp, obj);
    }

    /* ---- 10. 输出 HEX ---- */
    if (opt_hex) {
        c51_write_hex(out_fp, obj);
    }

    obj_free(obj);
    if (out_fp != stdout) fclose(out_fp);
    return 0;
}

#endif /* MINITEST_IMPLEMENTATION */