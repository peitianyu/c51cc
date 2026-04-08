#ifndef C51CC_OBJ_H
#define C51CC_OBJ_H

#include <stdint.h>
#include <stdio.h>
#include "list.h"

typedef enum { SEC_CODE, SEC_DATA, SEC_IDATA, SEC_XDATA, SEC_BIT, SEC_BDATA, SEC_PDATA } SectionKind;
typedef enum { SYM_FUNC, SYM_DATA, SYM_LABEL } SymbolKind;
typedef enum { RELOC_ABS8, RELOC_ABS16, RELOC_REL8, RELOC_REL16 } RelocKind;

enum {
	SYM_FLAG_GLOBAL = 1 << 0,
	SYM_FLAG_EXTERN = 1 << 1,
	SYM_FLAG_LOCAL  = 1 << 2,
	SYM_FLAG_BIT    = 1 << 3
};

typedef struct {
	char *name;
	SectionKind kind;
	int size;
	int align;
	unsigned char *bytes;
	int bytes_len;
	List *asminstrs; /* List<AsmInstr*> */
} Section;

typedef struct {
	char *name;
	SymbolKind kind;
	int section; /* -1 for undefined */
	int value;
	int size;
	unsigned flags;
} Symbol;

typedef struct {
	int section;
	int offset;
	RelocKind kind;
	char *symbol;
	int addend;
} Reloc;

typedef struct {
	char *op;
	List *args; /* List<char*> */
	char *ssa;  /* SSA comment (optional) */
} AsmInstr;

typedef struct {
	List *sections, *symbols, *relocs; /* List<Section*>, List<Symbol*>, List<Reloc*> */ 
} ObjFile;

ObjFile *obj_new(void);
void obj_free(ObjFile *obj);
int obj_add_section(ObjFile *obj, const char *name, SectionKind kind, int size, int align);
int obj_find_section(const ObjFile *obj, const char *name, SectionKind kind);
int obj_find_or_add_section(ObjFile *obj, const char *name, SectionKind kind, int align);
Section *obj_get_section(const ObjFile *obj, int index);

/* collection helpers */
void section_append_bytes(Section *sec, const unsigned char *bytes, int len);
void section_append_zeros(Section *sec, int count);

int obj_add_symbol(ObjFile *obj, const char *name, SymbolKind kind, int section, int value, int size, unsigned flags);
int obj_add_reloc(ObjFile *obj, int section, int offset, RelocKind kind, const char *symbol, int addend);

/* link */
ObjFile *obj_link(List *objs);
void print_link_summary(const ObjFile *out);

#endif /* C51CC_OBJ_H */
