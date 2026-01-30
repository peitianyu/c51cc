#ifndef C51CC_OBJ_H
#define C51CC_OBJ_H

#include <stdint.h>
#include <stdio.h>
#include "../list.h"

typedef enum {
	SEC_CODE,
	SEC_DATA,
	SEC_IDATA,
	SEC_XDATA,
	SEC_BIT,
	SEC_BDATA,
	SEC_PDATA
} SectionKind;

typedef enum {
	SYM_FUNC,
	SYM_DATA,
	SYM_LABEL
} SymbolKind;

typedef enum {
	RELOC_ABS8,
	RELOC_ABS16,
	RELOC_REL8,
	RELOC_REL16
} RelocKind;

enum {
	SYM_FLAG_GLOBAL = 1 << 0,
	SYM_FLAG_EXTERN = 1 << 1,
	SYM_FLAG_LOCAL  = 1 << 2
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
} AsmInstr;

typedef struct {
	List *sections; /* List<Section*> */
	List *symbols;  /* List<Symbol*> */
	List *relocs;   /* List<Reloc*> */
} ObjFile;

ObjFile *objfile_new(void);
void objfile_free(ObjFile *obj);
int objfile_add_section(ObjFile *obj, const char *name, SectionKind kind, int size, int align);
Section *objfile_get_section(ObjFile *obj, int index);

/* collection helpers */
void section_append_bytes(Section *sec, const unsigned char *bytes, int len);
void section_append_zeros(Section *sec, int count);

int objfile_add_symbol(ObjFile *obj, const char *name, SymbolKind kind, int section, int value, int size, unsigned flags);
int objfile_add_reloc(ObjFile *obj, int section, int offset, RelocKind kind, const char *symbol, int addend);

/* asm interface */
ObjFile *c51_asm_from_text(const char *text, char **error, int *error_line);

/* output helpers (asm/hex) */
int c51_write_asm(FILE *fp, const ObjFile *obj);
int c51_write_hex(FILE *fp, const ObjFile *obj);

#endif /* C51CC_OBJ_H */
