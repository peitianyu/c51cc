#include "obj.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void *obj_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "obj: out of memory\n");
        exit(1);
    }
    return p;
}

static char *obj_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = obj_alloc(len);
    memcpy(d, s, len);
    return d;
}

static AsmInstr *clone_asminstr(const AsmInstr *src)
{
    if (!src) return NULL;

    AsmInstr *dst = obj_alloc(sizeof(AsmInstr));
    dst->op = obj_strdup(src->op);
    dst->ssa = obj_strdup(src->ssa);
    dst->args = make_list();
    if (src->args) {
        for (Iter it = list_iter(src->args); !iter_end(it);) {
            char *arg = iter_next(&it);
            list_push(dst->args, obj_strdup(arg));
        }
    }
    return dst;
}

ObjFile *obj_new(void)
{
    ObjFile *obj = obj_alloc(sizeof(ObjFile));
    obj->sections = make_list();
    obj->symbols = make_list();
    obj->relocs = make_list();
    return obj;
}

static void free_asminstr(AsmInstr *ins)
{
    if (!ins) return;
    free(ins->op);
    if (ins->args) {
        list_free(ins->args);
        free(ins->args);
    }
    free(ins->ssa);
    free(ins);
}

static void free_section(Section *sec)
{
    if (!sec) return;
    free(sec->name);
    free(sec->bytes);
    if (sec->asminstrs) {
        for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
            free_asminstr(iter_next(&it));
        }
        free(sec->asminstrs);
    }
    free(sec);
}

void obj_free(ObjFile *obj)
{
    if (!obj) return;
    
    for (Iter it = list_iter(obj->sections); !iter_end(it);) 
        free_section(iter_next(&it));
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) 
        free(iter_next(&it));
    for (Iter it = list_iter(obj->relocs); !iter_end(it);) 
        free(iter_next(&it));
    
    free(obj->sections);
    free(obj->symbols);
    free(obj->relocs);
    free(obj);
}

int obj_add_section(ObjFile *obj, const char *name, SectionKind kind, int size, int align)
{
    if (!obj || !name) return -1;
    
    Section *sec = obj_alloc(sizeof(Section));
    sec->name = obj_strdup(name);
    sec->kind = kind;
    sec->size = sec->bytes_len = size;
    sec->align = align;
    sec->bytes = (size > 0) ? obj_alloc(size) : NULL;
    sec->asminstrs = make_list();
    
    list_push(obj->sections, sec);
    return obj->sections->len - 1;
}

Section *obj_get_section(const ObjFile *obj, int index)
{
    return obj ? list_get(obj->sections, index) : NULL;
}

int obj_add_symbol(ObjFile *obj, const char *name, SymbolKind kind, 
                       int section, int value, int size, unsigned flags)
{
    if (!obj || !name) return -1;
    
    Symbol *sym = obj_alloc(sizeof(Symbol));
    sym->name = obj_strdup(name);
    sym->kind = kind;
    sym->section = section;
    sym->value = value;
    sym->size = size;
    sym->flags = flags;
    
    list_push(obj->symbols, sym);
    return obj->symbols->len - 1;
}

int obj_add_reloc(ObjFile *obj, int section, int offset, 
                      RelocKind kind, const char *symbol, int addend)
{
    if (!obj || !symbol) return -1;
    
    Reloc *rel = obj_alloc(sizeof(Reloc));
    rel->section = section;
    rel->offset = offset;
    rel->kind = kind;
    rel->symbol = obj_strdup(symbol);
    rel->addend = addend;
    
    list_push(obj->relocs, rel);
    return obj->relocs->len - 1;
}

static void section_resize(Section *sec, int new_len)
{
    sec->bytes = realloc(sec->bytes, new_len);
    if (!sec->bytes) {
        fprintf(stderr, "obj: out of memory\n");
        exit(1);
    }
    sec->bytes_len = sec->size = new_len;
}

void section_append_zeros(Section *sec, int count)
{
    if (!sec || count <= 0) return;
    
    int old_len = sec->bytes_len;
    section_resize(sec, old_len + count);
    memset(sec->bytes + old_len, 0, count);
}

void section_append_bytes(Section *sec, const unsigned char *bytes, int len)
{
    if (!sec || !bytes || len <= 0) return;
    
    int old_len = sec->bytes_len;
    section_resize(sec, old_len + len);
    memcpy(sec->bytes + old_len, bytes, len);
}

// 链接相关函数
static const char *section_default_name(SectionKind kind)
{
    static const char *names[] = {
        [SEC_CODE] = ".text", [SEC_DATA] = ".data", [SEC_IDATA] = ".idata",
        [SEC_XDATA] = ".xdata", [SEC_BIT] = ".bit", [SEC_BDATA] = ".bdata",
        [SEC_PDATA] = ".pdata"
    };
    return names[kind < 7 ? kind : SEC_CODE];
}

static int align_up(int value, int align)
{
    return (align <= 1) ? value : ((value + align - 1) / align) * align;
}

static Section *ensure_out_section(ObjFile *out, SectionKind kind)
{
    for (Iter it = list_iter(out->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == kind) return sec;
    }
    int idx = obj_add_section(out, section_default_name(kind), kind, 0, 1);
    return obj_get_section(out, idx);
}

typedef struct {
    ObjFile *obj;
    int in_sec, out_sec, base;
} SectionMap;

static SectionMap *find_map(List *maps, ObjFile *obj, int in_sec)
{
    for (Iter it = list_iter(maps); !iter_end(it);) {
        SectionMap *m = iter_next(&it);
        if (m && m->obj == obj && m->in_sec == in_sec) return m;
    }
    return NULL;
}

static Symbol *find_symbol_by_name(ObjFile *obj, const char *name)
{
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && name && !strcmp(sym->name, name)) return sym;
    }
    return NULL;
}

static int apply_reloc(Reloc *rel, Section *sec, Symbol *sym)
{
    if (!rel || !sec || !sec->bytes) return -1;
    
    int sym_addr = sym->value + rel->addend;
    int offset = rel->offset;
    
    if (offset < 0 || offset >= sec->bytes_len) return -1;
    
    switch (rel->kind) {
        case RELOC_ABS8:
            if (offset + 1 > sec->bytes_len) return -1;
            sec->bytes[offset] = (unsigned char)(sym_addr & 0xFF);
            break;
            
        case RELOC_ABS16:
            if (offset + 2 > sec->bytes_len) return -1;
            sec->bytes[offset] = (unsigned char)((sym_addr >> 8) & 0xFF);
            sec->bytes[offset + 1] = (unsigned char)(sym_addr & 0xFF);
            break;
            
        case RELOC_REL8:
            if (offset + 1 > sec->bytes_len) return -1;
            sec->bytes[offset] = (unsigned char)((sym_addr - offset - 1) & 0xFF);
            break;
            
        case RELOC_REL16:
            if (offset + 2 > sec->bytes_len) return -1;
            int relv = sym_addr - offset - 2;
            sec->bytes[offset] = (unsigned char)((relv >> 8) & 0xFF);
            sec->bytes[offset + 1] = (unsigned char)(relv & 0xFF);
            break;
            
        default:
            return -1;
    }
    return 0;
}

static int apply_relocs(ObjFile *out)
{
    if (!out) return -1;
    
    for (Iter it = list_iter(out->relocs); !iter_end(it);) {
        Reloc *rel = iter_next(&it);
        if (!rel) continue;
        
        Section *sec = obj_get_section(out, rel->section);
        Symbol *sym = find_symbol_by_name(out, rel->symbol);
        
        if (!sec || !sym || sym->section == -1) {
            fprintf(stderr, "obj: undefined symbol '%s' for relocation\n", rel->symbol);
            return -1;
        }
        
        if (apply_reloc(rel, sec, sym) != 0) return -1;
    }
    return 0;
}

static int section_index(ObjFile *out, Section *sec)
{
    int idx = 0;
    for (Iter it = list_iter(out->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

ObjFile *obj_link(List *objs)
{
    if (!objs) return NULL;
    
    ObjFile *out = obj_new();
    List *maps = make_list();
    
    // 合并所有节
    for (Iter oit = list_iter(objs); !iter_end(oit);) {
        ObjFile *obj = iter_next(&oit);
        if (!obj) continue;
        
        int sec_idx = 0;
        for (Iter sit = list_iter(obj->sections); !iter_end(sit); ++sec_idx) {
            Section *in = iter_next(&sit);
            if (!in) continue;
            
            Section *out_sec = ensure_out_section(out, in->kind);
            int align = in->align > 0 ? in->align : 1;
            int base = align_up(out_sec->bytes_len, align);
            
            // 对齐填充
            if (base > out_sec->bytes_len)
                section_append_zeros(out_sec, base - out_sec->bytes_len);
            
            if (out_sec->align < align) out_sec->align = align;
            
            // 复制数据
            if (in->bytes && in->bytes_len > 0)
                section_append_bytes(out_sec, in->bytes, in->bytes_len);
            else if (in->size > 0)
                section_append_zeros(out_sec, in->size);

            if (in->asminstrs) {
                for (Iter ait = list_iter(in->asminstrs); !iter_end(ait);) {
                    AsmInstr *ins = iter_next(&ait);
                    AsmInstr *copy = clone_asminstr(ins);
                    if (copy) list_push(out_sec->asminstrs, copy);
                }
            }
            
            // 记录映射关系
            SectionMap *m = obj_alloc(sizeof(SectionMap));
            m->obj = obj;
            m->in_sec = sec_idx;
            m->out_sec = section_index(out, out_sec);
            m->base = base;
            list_push(maps, m);
        }
        
        // 处理符号
        for (Iter sit = list_iter(obj->symbols); !iter_end(sit);) {
            Symbol *sym = iter_next(&sit);
            if (!sym) continue;
            
            int sec = sym->section, val = sym->value;
            if (sec >= 0) { // 正常符号
                SectionMap *m = find_map(maps, obj, sec);
                if (m) { sec = m->out_sec; val = m->base + sym->value; }
            }
            
            obj_add_symbol(out, sym->name, sym->kind, sec, val, sym->size, sym->flags);
        }
        
        // 处理重定位
        for (Iter rit = list_iter(obj->relocs); !iter_end(rit);) {
            Reloc *rel = iter_next(&rit);
            if (!rel) continue;
            
            SectionMap *m = find_map(maps, obj, rel->section);
            if (m) {
                obj_add_reloc(out, m->out_sec, m->base + rel->offset, 
                                 rel->kind, rel->symbol, rel->addend);
            }
        }
    }
    
    // 清理映射表
    for (Iter it = list_iter(maps); !iter_end(it);) free(iter_next(&it));
    free(maps);
    
    // 应用重定位
    if (apply_relocs(out) != 0) {
        obj_free(out);
        return NULL;
    }
    
    return out;
}

void print_link_summary(const ObjFile *out)
{
    if (!out) return;
    
    fputs("\n==== Link Map ====\n", stderr);
    
    // 节信息
    Iter it = list_iter(out->sections);
    while (!iter_end(it)) {
        Section *sec = iter_next(&it);
        if (sec) {
            fprintf(stderr, "section %-6s  size=%-4d  align=%d\n",
                    sec->name, sec->bytes_len, sec->align);
        }
    }
    
    // 符号信息
    it = list_iter(out->symbols);
    while (!iter_end(it)) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name) {
            const char *sec_name = sym->section == -2 ? "abs" :
                                   sym->section >= 0 ? 
                                       ((Section*)list_get(out->sections, sym->section))->name : "?";
            
            fprintf(stderr, "symbol %-16s  sec=%-6s  value=0x%04X\n",
                    sym->name, sec_name, sym->value);
        }
    }
    
    fputs("==== End Link Map ====\n", stderr);
}