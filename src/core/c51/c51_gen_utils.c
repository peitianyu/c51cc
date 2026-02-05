#include "c51_gen.h"

/* === Global state === */
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

/* === Core utilities === */
void *gen_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "c51_gen: out of memory\n");
        exit(1);
    }
    return p;
}

char *gen_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = gen_alloc(len);
    memcpy(d, s, len);
    return d;
}

/* === Parsing helpers === */
bool is_ident(const char *s)
{
    if (!s || !*s) return false;
    if (!( (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_' ))
        return false;
    for (const char *p = s + 1; *p; ++p) {
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' ))
            return false;
    }
    return true;
}

bool parse_int_val(const char *s, int *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s || (end && *end != '\0')) return false;
    if (out) *out = (int)v;
    return true;
}

int parse_reg_rn(const char *s)
{
    if (!s) return -1;
    if ((s[0] == 'r' || s[0] == 'R') && s[1] >= '0' && s[1] <= '7' && s[2] == '\0')
        return s[1] - '0';
    if ((s[0] == 'a' || s[0] == 'A') && (s[1] == 'r' || s[1] == 'R') &&
        s[2] >= '0' && s[2] <= '7' && s[3] == '\0')
        return s[2] - '0';
    return -1;
}

int parse_indirect_rn(const char *s)
{
    if (!s || s[0] != '@' || s[1] != 'r' || s[2] < '0' || s[2] > '7' || s[3] != '\0') return -1;
    return s[2] - '0';
}

bool parse_immediate(const char *s, int *out)
{
    if (!s || s[0] != '#') return false;
    return parse_int_val(s + 1, out);
}

bool parse_direct(const char *s, int *out)
{
    if (!s || !*s) return false;
    if (!strcmp(s, "B")) { if (out) *out = 0xF0; return true; }
    if (!strcmp(s, "A")) { if (out) *out = 0xE0; return true; }
    return parse_int_val(s, out);
}

bool parse_direct_symbol(const char *s, int *out, const char **label)
{
    if (parse_direct(s, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && s && is_ident(s)) {
        *label = s;
        if (out) *out = 0;
        return true;
    }
    return false;
}

bool parse_bit_symbol(const char *s, int *out, const char **label)
{
    if (!s || !*s) return false;
    if (!strcmp(s, "A.0") || !strcmp(s, "ACC.0")) {
        if (out) *out = 0xE0;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.1") || !strcmp(s, "ACC.1")) {
        if (out) *out = 0xE1;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.2") || !strcmp(s, "ACC.2")) {
        if (out) *out = 0xE2;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.3") || !strcmp(s, "ACC.3")) {
        if (out) *out = 0xE3;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.4") || !strcmp(s, "ACC.4")) {
        if (out) *out = 0xE4;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.5") || !strcmp(s, "ACC.5")) {
        if (out) *out = 0xE5;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.6") || !strcmp(s, "ACC.6")) {
        if (out) *out = 0xE6;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.7") || !strcmp(s, "ACC.7")) {
        if (out) *out = 0xE7;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "B.0")) { if (out) *out = 0xF0; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.1")) { if (out) *out = 0xF1; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.2")) { if (out) *out = 0xF2; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.3")) { if (out) *out = 0xF3; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.4")) { if (out) *out = 0xF4; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.5")) { if (out) *out = 0xF5; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.6")) { if (out) *out = 0xF6; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.7")) { if (out) *out = 0xF7; if (label) *label = NULL; return true; }
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

bool parse_immediate_label(const char *s, int *out, const char **label)
{
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

/* === Type/section helpers === */
SectionKind map_data_space(Ctype *type)
{
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

bool is_signed_type(Ctype *type)
{
    if (!type) return true;
    CtypeAttr a = get_attr(type->attr);
    if (a.ctype_unsigned) return false;
    return true;
}

bool is_register_mmio(Ctype *type)
{
    if (!type) return false;
    return get_attr(type->attr).ctype_register != 0;
}

bool is_register_bit(Ctype *type)
{
    return is_register_mmio(type) && type->type == CTYPE_BOOL;
}

/* === Data space === */
int data_space_kind(Ctype *type)
{
    if (!type) return 1;
    int d = get_attr(type->attr).ctype_data;
    return d ? d : 1;
}

bool func_stack_offset(Func *f, const char *name, int *out)
{
    if (!f || !name || !f->stack_offsets) return false;
    int *p = (int *)dict_get(f->stack_offsets, (char *)name);
    if (!p) return false;
    if (out) *out = *p;
    return true;
}
