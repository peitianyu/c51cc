#include "c51_obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ObjFile *c51_link(List *objs)
{
    return obj_link(objs);
}

#ifdef MINITEST_IMPLEMENTATION
#include "../minitest.h"
#include "../ssa.h"

static char *test_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = malloc(len);
    if (!d) {
        fprintf(stderr, "c51_link: out of memory\n");
        exit(1);
    }
    memcpy(d, s, len);
    return d;
}

extern List *ctypes;
extern List *strings;
extern void parser_reset(void);
extern List *read_toplevels(void);
extern void set_current_filename(const char *filename);
extern char *ast_to_string(Ast *ast);
ObjFile *c51_gen_from_ssa(void *ssa);

TEST(test, c51_link) {
    char line[256];
    List *files = make_list();
    printf("file path(s) for C51 link test (empty line to end): ");
    while (fgets(line, sizeof line, stdin)) {
        char *path = strtok(line, "\n");
        if (!path || !*path) break;
        list_push(files, test_strdup(path));
    }
    if (files->len == 0)
        puts("open fail"), exit(1);

    List *objs = make_list();
    for (Iter fit = list_iter(files); !iter_end(fit);) {
        char *infile = iter_next(&fit);
        if (!pp_preprocess_to_stdin(infile))
            puts("preprocess fail"), exit(1);

        set_current_filename(infile);
        parser_reset();

        SSABuild *b = ssa_build_create();
        List *toplevels = read_toplevels();

        printf("\n=== Parsing AST (%s) ===\n", infile);
        for (Iter i = list_iter(toplevels); !iter_end(i);) {
            Ast *v = iter_next(&i);
            printf("ast: %s\n", ast_to_string(v));
            ssa_convert_ast(b, v);
        }

        ssa_optimize(b->unit, OPT_O1);

        ObjFile *obj = c51_gen_from_ssa(b->unit);
        ASSERT(obj);
        list_push(objs, obj);
        ssa_build_destroy(b);
        parser_reset();
    }

    ObjFile *out = c51_link(objs);
    
    print_link_summary(out);
    
    ASSERT(out);

    printf("\n=== ASM Output (link) ===\n");
    ASSERT_EQ(c51_write_asm(stdout, out), 0);

    printf("\n=== HEX Output (link) ===\n");
    ASSERT_EQ(c51_write_hex(stdout, out), 0);

    objfile_free(out);
    list_free(files);
    free(files);
    list_free(objs);
    free(objs);
}
#endif
