#include "ssa.h"
#include "cc.h"

static SSABuild *ssa_new()
{
    SSABuild *s = malloc(sizeof(SSABuild));
    s->unit = malloc(sizeof(SSAUnit));
    s->unit->funcs = make_list();
    s->unit->globals = make_list();
    s->cur_func = NULL;
    s->cur_block = NULL;

    s->instr_buf = make_list();
    s->name_buf = make_list();
    return s;
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

TEST(test, ssa) {
    char infile[256];
    printf("file path: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);

    SSABuild *b = ssa_new();
        
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("%s", ast_to_string(v));
    }
    list_free(cstrings);
    list_free(ctypes);

    printf("\n");
}
#endif /* MINITEST_IMPLEMENTATION */