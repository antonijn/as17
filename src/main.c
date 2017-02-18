/*
 * Assembler for the fictional RUN1617 CPU
 * Copyright (C) 2017  Antonie Blom
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum value_kind {
	/* immediate constant */
	VK_IMM,
	/* register */
	VK_REG,
	/* label */
	VK_LABEL,
	/* memory dereference */
	VK_MEM
};

struct value;

/* Representing a dereference `[reg + imm]' */
struct mem_value {
	unsigned reg;
	/* signed immediate constant or label */
	struct value *offset;
};

/* A value as seen in operands */
struct value {
	enum value_kind kind;

	union {
		unsigned imm;
		unsigned reg;
		char *label;
		struct mem_value mem;
	} val;
};

/* Value node */
struct value_nd {
	struct value val;

	struct value_nd *next;
};

struct instr {
	int line;
	char *mnem;
	unsigned cond;
	int addr_offset;

	/* operands */
	struct value_nd *ops;
};

/* Instruction node */
struct instr_nd {
	struct instr instr;

	struct instr_nd *next;
};

/* Initialize the lexer */
static int lxinit();
/* Advance the lexer */
static int lxadv();

/* Parse the entire ASM AST from `stdin' into the `first_instr' linked
 * list */
static int parse();

/* Cleanup functions */
static void cleanup();
static void cleanup_value(struct value *val);
static void cleanup_operands(struct value_nd *first);
static void cleanup_instrs(struct instr_nd *first);

/* Case-insensitive strcmp() */
static int ci_strcmp(char *a, char *b);

/* Assemble the AST to machine code */
static int assemble(void);

/*  _         _
 * | |_____ _(_)_ _  __ _
 * | / -_) \ / | ' \/ _` |
 * |_\___/_\_\_|_||_\__, |
 *                  |___/
 */

enum tok_kind {
	TK_WORD,
	TK_REG, /* register */
	TK_COLON,
	TK_DOT,
	TK_COMMA,
	TK_PLUS,
	TK_LSQRBRACKET,
	TK_RSQRBRACKET,
	TK_HEXNUM,
	TK_OCTNUM,
	TK_DECNUM,
	TK_EOL, /* end of line */
	TK_EOF /* end of file */
};

#define MAXLXLEN 31
#define TOK_TOO_LONG_STR "token too long (max 31)"

/* The current lexer location */
static int cur_line = 1;

struct tok {
	enum tok_kind kind;
	char lexeme[MAXLXLEN + 1];
};

/* Current token being analyzed */
struct tok cur_tok;


/* The character currently being analyzed by the lexer */
static int cur_char;

static int
ci_strcmp(char *a, char *b)
{
	int i;
	for (i = 0; ; ++i) {
		int cha, chb;

		cha = toupper(a[i]);
		chb = toupper(b[i]);

		if (cha != chb)
			return cha - chb;

		if (!cha)
			break;
	}
	return 0;
}

/* Write a parser error to stderr */
static void
parser_err(char *msg)
{
	fprintf(stderr, "ln %d: parser error: %s\n", cur_line, msg);
}

/* Advance the lexer state by one character */
static void
lxadvch(void)
{
	cur_char = getchar();
}

/* Reads word or register token */
static int
lxreadword(void)
{
	int i = 0;

	assert(isalpha(cur_char) || cur_char == '_');

	while (isalnum(cur_char) || cur_char == '_') {
		if (i >= MAXLXLEN) {
			parser_err(TOK_TOO_LONG_STR);
			return -1;
		}

		cur_tok.lexeme[i++] = cur_char;
		lxadvch();
	}

	cur_tok.lexeme[i] = '\0';

	/* this is a bit of a mess...
	 * checks if word is an actual word or a register name */

	if (!ci_strcmp(cur_tok.lexeme, "zero")
	 || !ci_strcmp(cur_tok.lexeme, "rsp")
	 || !ci_strcmp(cur_tok.lexeme, "rip"))
	{
		/* zero, rsp and rip are reg names */
		cur_tok.kind = TK_REG;
	} else if (toupper(cur_tok.lexeme[0]) == 'R') {
		/* might be a register name... */

		int regnum;
		if (sscanf(&cur_tok.lexeme[1], "%d", &regnum) < 1) {
			cur_tok.kind = TK_WORD;
		} else if (regnum < 0 || regnum > 15) {
			parser_err("invalid register");
			return -1;
		} else {
			cur_tok.kind = TK_REG;
		}

	} else {
		cur_tok.kind = TK_WORD;
	}

	return 0;
}

/* Test if `ch' is digit in base `base' */
static int
isdigit_b(int ch, int base)
{
	if (isdigit(ch))
		return -1;

	if (base > 10) {
		ch = toupper(ch);
		ch -= 'A';
		if (ch >= 0 && ch < (base - 10))
			return -1;
	}

	return 0;
}

/*
 * Read a number token in base `base'.
 * `negative` indicates whether the number should be read as negative
 * or not.
 *
 * Only bases 8, 10 and 16 are supported.
 */
static int
lxreadnum_b(int base, int negative)
{
	int i;

	/* negative number handling is quite hacky...
	 * deal with it */

	char pfx[4] = { 0 };
	if (negative)
		strcpy(pfx, "-");

	switch (base) {
	case 8:
		cur_tok.kind = TK_OCTNUM;
		strcat(pfx, "0");
		break;
	case 16:
		cur_tok.kind = TK_HEXNUM;
		strcat(pfx, "0x");
		break;
	case 10:
		cur_tok.kind = TK_DECNUM;
		break;
	default:
		assert(0);
	}

	strcpy(cur_tok.lexeme, pfx);
	i = strlen(pfx);

	while (isdigit_b(cur_char, base)) {
		if (i >= MAXLXLEN) {
			parser_err(TOK_TOO_LONG_STR);
			return -1;
		}

		cur_tok.lexeme[i++] = cur_char;
		lxadvch();
	}

	cur_tok.lexeme[i] = '\0';

	return 0;
}

/* Read any number token */
static int
lxreadnum()
{
	int fst_ch;
	int negative = 0;

	assert(isdigit(cur_char) || cur_char == '-');

	if (cur_char == '-') {
		negative = 1;
		lxadvch();
	}

	fst_ch = cur_char;
	lxadvch();

	if (fst_ch == '0') {
		if (toupper(cur_char) == 'X') {
			lxadvch();
			return lxreadnum_b(16, negative);
		}

		if (isdigit_b(cur_char, 8))
			return lxreadnum_b(8, negative);
	}

	/* unpeek */
	ungetc(cur_char, stdin);
	cur_char = fst_ch;

	return lxreadnum_b(10, negative);
}

/* Advance `cur_tok' to the next token */
static int
lxadv(void)
{
	/* skip whitespace */
	while (isspace(cur_char) && cur_char != '\n')
		lxadvch();

	if (isalpha(cur_char) || cur_char == '_')
		return lxreadword();

	if (isdigit(cur_char) || cur_char == '-')
		return lxreadnum();

	if (cur_char == '.') {
		cur_tok.kind = TK_DOT;
		strcpy(cur_tok.lexeme, ".");
		lxadvch();
		return 0;
	}

	if (cur_char == ',') {
		cur_tok.kind = TK_COMMA;
		strcpy(cur_tok.lexeme, ",");
		lxadvch();
		return 0;
	}

	if (cur_char == '[') {
		cur_tok.kind = TK_LSQRBRACKET;
		strcpy(cur_tok.lexeme, "[");
		lxadvch();
		return 0;
	}
	if (cur_char == ']') {
		cur_tok.kind = TK_RSQRBRACKET;
		strcpy(cur_tok.lexeme, "]");
		lxadvch();
		return 0;
	}

	if (cur_char == '+') {
		cur_tok.kind = TK_PLUS;
		strcpy(cur_tok.lexeme, "+");
		lxadvch();
		return 0;
	}

	if (cur_char == ':') {
		cur_tok.kind = TK_COLON;
		strcpy(cur_tok.lexeme, ":");
		lxadvch();
		return 0;
	}

	if (cur_char == '\n') {
		++cur_line;
		cur_tok.kind = TK_EOL;
		strcpy(cur_tok.lexeme, "\n");
		lxadvch();
		return 0;
	}

	if (cur_char == EOF) {
		cur_tok.kind = TK_EOF;
		return 0;
	}

	parser_err("unexpected character");
	return -1;
}

/* Initialize the lexer: set `cur_tok' to the first token in `stdin' */
static int
lxinit(void)
{
	lxadvch();
	return lxadv();
}

/*                    _
 *  _ __  __ _ _ _ __(_)_ _  __ _
 * | '_ \/ _` | '_(_-< | ' \/ _` |
 * | .__/\__,_|_| /__/_|_||_\__, |
 * |_|                      |___/
 */

static struct instr_nd *first_instr = NULL;

/* Label-instruction key-value-pair for in the hash table */
struct label_kvp {
	char *label;
	int hash;
	struct instr *instr;

	struct label_kvp *next;
};

/* Hash table linking label names to instructions */
#define LABELS_HTABLE_MASK 0xff
struct label_kvp *labels[LABELS_HTABLE_MASK + 1] = { 0 };

/* Sipmle string hash */
static unsigned
djb2(char *str)
{
	unsigned hash = 5381;
	int c;
	while (c = *str++)
		hash = ((hash << 5) + hash) + c;

	return hash;
}

/* Get a pointer to the `struct instr *' with label `label', or NULL
 * if such an instruction does not exist */
static struct instr **
labels_get_ptr(char *label)
{
	unsigned hash = djb2(label);
	struct label_kvp *found;

	found = labels[hash & LABELS_HTABLE_MASK];
	for (found = labels[hash & LABELS_HTABLE_MASK]; found; found = found->next)
		if (found->hash == hash && !strcmp(label, found->label))
			return &found->instr;

	return NULL;
}

/* Get the `struct instr *' with label `label', or NULL if such an
 * instruction does not exist */
static struct instr *
labels_get(char *label)
{
	struct instr **i = labels_get_ptr(label);
	if (i)
		return *i;
	return NULL;
}

/* Connect `label' to `instr' in the label hashtable */
static int
labels_set(char *label, struct instr *instr)
{
	unsigned hash;
	struct label_kvp *ins;
	size_t lablen;
	struct instr **ins_set;

	hash = djb2(label);

	if ((ins_set = labels_get_ptr(label)) == NULL) {
		ins = malloc(sizeof(struct label_kvp));
		if (!ins)
			return -1;

		lablen = strlen(label) + 1;
		ins->label = malloc(lablen);
		if (!ins->label)
			return -1;

		memcpy(ins->label, label, lablen);

		ins->hash = hash;
		ins_set = &ins->instr;

		hash &= LABELS_HTABLE_MASK;
		ins->next = labels[hash];
		labels[hash] = ins;
	}

	*ins_set = instr;

	return 0;
}

static int
cond_from_str(char *str)
{
	struct condstr {
		char *str;
		unsigned cond;
	};
	static struct condstr strings[] = {
		{ "Z", 0x0 }, { "E", 0x0 },
		{ "NZ", 0x1 }, { "NE", 0x1 },
		{ "C", 0x2 }, { "GEU", 0x2 },
		{ "NC", 0x3 }, { "LU", 0x3 },
		{ "N", 0x4 },
		{ "NN", 0x5 },
		{ "O", 0x6 },
		{ "NO", 0x7 },
		{ "GU", 0x8 },
		{ "LEU", 0x9 },
		{ "GE", 0xA },
		{ "L", 0xB },
		{ "G", 0xC },
		{ "LE", 0xD },
		{ "F", 0xE },
		{ "T", 0xF },
	};
	int i;

	for (i = 0; i < sizeof(strings) / sizeof(strings[0]); ++i)
		if (!ci_strcmp(strings[i].str, str))
			return strings[i].cond;

	return -1;
}

/*
 * Parse a single expression
 * NOTE: leaves `cur_tok' at the token after the expression
 */
static int parse_expr(struct value *val);

/*
 * Parse a label token to a value `val'
 * NOTE: leaves `cur_tok' at the label token
 */
static int
parse_label(struct value *val)
{
	size_t lab_size;

	val->kind = VK_LABEL;

	lab_size = strlen(cur_tok.lexeme) + 1;
	val->val.label = malloc(lab_size);
	if (!val->val.label)
		return -1;
	memcpy(val->val.label, cur_tok.lexeme, lab_size);

	return 0;
}

/*
 * Parse a memory expression into `val'
 * NOTE: leaves `cur_tok' at the `]' character
 */
static int
parse_lsqr(struct value *val)
{
	struct value reg;
	enum value_kind kind;

	assert(cur_tok.kind == TK_LSQRBRACKET);

	val->kind = VK_MEM;

	if (lxadv() < 0)
		return -1;

	if (parse_expr(&reg) < 0)
		return -1;

	if (reg.kind != VK_REG) {
		parser_err("expected register");
		cleanup_value(&reg);
		return -1;
	}

	val->val.mem.reg = reg.val.reg;
	val->val.mem.offset = NULL;

	if (cur_tok.kind == TK_PLUS) {
		if (lxadv() < 0)
			return -1;

		val->val.mem.offset = malloc(sizeof(struct value));
		if (!val->val.mem.offset)
			return -1;

		if (parse_expr(val->val.mem.offset) < 0) {
			free(val->val.mem.offset);
			return -1;
		}

		kind = val->val.mem.offset->kind;
		if (kind != VK_IMM && kind != VK_LABEL) {
			parser_err("expected immediate constant or label");
			cleanup_value(val->val.mem.offset);
			free(val->val.mem.offset);
			return -1;
		}
	}

	if (cur_tok.kind != TK_RSQRBRACKET) {
		parser_err("expected `]'");
		cleanup_value(val->val.mem.offset);
		return -1;
	}

	return 0;
}

static int
parse_expr(struct value *val)
{
	switch (cur_tok.kind) {
	case TK_WORD:
		if (parse_label(val) < 0)
			return -1;
		break;

	case TK_LSQRBRACKET:
		if (parse_lsqr(val) < 0)
			return -1;
		break;

	case TK_DECNUM:
		val->kind = VK_IMM;
		sscanf(cur_tok.lexeme, "%u", &val->val.imm);
		break;

	case TK_OCTNUM:
		val->kind = VK_IMM;
		sscanf(cur_tok.lexeme, "%o", &val->val.imm);
		break;

	case TK_HEXNUM:
		val->kind = VK_IMM;
		sscanf(cur_tok.lexeme, "%x", &val->val.imm);
		break;

	case TK_REG:
		val->kind = VK_REG;
		if (!ci_strcmp(cur_tok.lexeme, "zero"))
			val->val.reg = 0;
		else if (!ci_strcmp(cur_tok.lexeme, "rsp"))
			val->val.reg = 14;
		else if (!ci_strcmp(cur_tok.lexeme, "rip"))
			val->val.reg = 15;
		else
			sscanf(&cur_tok.lexeme[1], "%u", &val->val.reg);
		break;

	default:
		parser_err("unexpected token");
		return -1;
	}

	return lxadv();
}

/*
 * Parse a single instruction operand expression into `nd'
 * NOTE: leaves `cur_tok' at the first token after the `,' character
 */
static int
parse_operand(struct value_nd **nd)
{
	struct value_nd *new_nd;

	if (cur_tok.kind == TK_EOL || cur_tok.kind == TK_EOF) {
		*nd = NULL;
		return 0;
	}

	new_nd = malloc(sizeof(struct value_nd));
	if (!new_nd)
		return -1;
	new_nd->next = NULL;

	if (parse_expr(&new_nd->val) < 0) {
		free(new_nd);
		return -1;
	}

	if (cur_tok.kind == TK_COMMA) {
		if (lxadv() < 0) {
			free(new_nd);
			return -1;
		}

		if (cur_tok.kind == TK_EOL || cur_tok.kind == TK_EOF) {
			parser_err("unexpected end-of-line");
			cleanup_operands(new_nd);
			return -1;
		}
	}

	*nd = new_nd;
	return 0;
}

/*
 * Parse an entire instruction line into `nd', including any possible label,
 * using `offs' as the absolute memory instruction offset, increasing its
 * value by four.
 * NOTE: leaves `cur_tok' at the first token after the instruction
 */
static int
parse_instr(struct instr_nd **nd, int *offs)
{
	struct tok label_tok, fst;
	char *label, *mnem;
	size_t mnem_size;
	unsigned cond;
	int line;

	struct value_nd *first, **ops_nd;
	struct instr_nd *new_nd;

	while (cur_tok.kind == TK_EOL)
		if (lxadv() < 0)
			return -1;

	if (cur_tok.kind == TK_EOF) {
		*nd = NULL;
		return 0;
	}

	if (cur_tok.kind != TK_WORD) {
		parser_err("expected word");
		return -1;
	}

	label_tok = cur_tok;
	if (lxadv() < 0)
		return -1;

	if (cur_tok.kind == TK_COLON) {
		/* we're dealing with a label */
		label = &label_tok.lexeme[0];

		if (lxadv() < 0)
			return -1;

		while (cur_tok.kind == TK_EOL)
			if (lxadv() < 0)
				return -1;

		if (cur_tok.kind != TK_WORD) {
			parser_err("expected word");
			return -1;
		}

		fst = cur_tok;
		if (lxadv() < 0)
			return -1;
	} else {
		label = NULL;
		fst = label_tok;
	}

	line = cur_line;

	/* `fst' now contains the first token in the
	 * instruction line, the next token is now `cur_tok' */

	if (cur_tok.kind == TK_DOT) {
		int scond;

		if (lxadv() < 0)
			return -1;

		scond = cond_from_str(cur_tok.lexeme);
		if (scond < 0) {
			parser_err("unknown condition");
			return -1;
		}

		cond = scond;
		if (lxadv() < 0)
			return -1;
	} else {
		cond = 0xF;
	}

	/* read operands */

	first = NULL;
	ops_nd = &first;
	for (;;) {
		if (parse_operand(ops_nd) < 0)
			goto stop_ops;

		if (*ops_nd == NULL)
			break;

		(*ops_nd)->next = NULL;
		ops_nd = &(*ops_nd)->next;
	}

	/* initialize new node */

	new_nd = malloc(sizeof(struct instr_nd));
	if (!new_nd)
		goto stop_ops;

	mnem_size = strlen(fst.lexeme) + 1;
	mnem = malloc(mnem_size);
	if (!mnem)
		goto stop_new_nd;
	memcpy(mnem, fst.lexeme, mnem_size);

	new_nd->instr.mnem = mnem;
	new_nd->instr.cond = cond;
	new_nd->instr.addr_offset = *offs;
	*offs += 4;
	new_nd->instr.line = line;
	new_nd->instr.ops = first;
	new_nd->next = NULL;

	if (label) {
		if (labels_get(label)) {
			parser_err("a label with that name already exists");
			goto stop_mnem;
		}
		if (labels_set(label, &new_nd->instr) < 0)
			goto stop_mnem;
	}

	*nd = new_nd;
	return 0;

	/* abort landing pads */
stop_mnem:
	free(mnem);

stop_new_nd:
	free(new_nd);

stop_ops:
	cleanup_operands(first);
	return -1;
}

static int
parse(void)
{
	int offs = 0;
	struct instr_nd **last = &first_instr;

	if (lxinit() < 0)
		return -1;

	for (;;) {
		if (parse_instr(last, &offs) < 0)
			return -1;

		if (!*last)
			break;

		last = &(*last)->next;
	}

	return 0;
}


/*                        _    _
 *  __ _ ______ ___ _ __ | |__| |___
 * / _` (_-<_-</ -_) '  \| '_ \ / -_)
 * \__,_/__/__/\___|_|_|_|_.__/_\___|
 */

/* The emit_*() functions write binary instructions to `stdout' */

static void
emit_u(unsigned u)
{
	putchar((u >> 24) & 0xFFU);
	putchar((u >> 16) & 0xFFU);
	putchar((u >> 8) & 0xFFU);
	putchar((u >> 0) & 0xFFU);
}

static void
emit_halt(unsigned cond)
{
	emit_u(0xFFFFFFF0U | cond);
}

static void
emit_read(unsigned c10, unsigned ra, unsigned rd, unsigned cond)
{
	assert((c10 & ~0x3FFU) == 0);
	emit_u(0xC0000000U | (c10 << 16) | (ra << 8) | (rd << 4) | cond);
}

static void
emit_write(unsigned c10, unsigned rb, unsigned ra, unsigned cond)
{
	assert((c10 & ~0x3FFU) == 0);
	emit_u(0xE0000000U | (c10 << 16) | (rb << 12) | (ra << 8) | cond);
}

static void
emit_push(unsigned ra, unsigned cond)
{
	emit_u(0xC4000EE0U | (ra << 12) | cond);
}

static void
emit_pop(unsigned rd, unsigned cond)
{
	emit_u(0xD00000E0U | (rd << 4) | cond);
}

static void
emit_loadhi(unsigned c22, unsigned rd, unsigned cond)
{
	assert((c22 & ~0x3FFFFF) == 0);
	emit_u(0x80000000U | (c22 << 8) | (rd << 4) | cond);
}

static void
emit_arith_reg(unsigned opcode, unsigned flg, unsigned ra, unsigned rb, unsigned rd, unsigned cond)
{
	assert((opcode & ~0x7U) == 0);
	assert((flg & ~0x1U) == 0);
	emit_u(0x04000000U | (opcode << 28) | (flg << 27) | (ra << 12) | (rb << 8) | (rd << 4) | cond);
}

static void
emit_arith_imm(unsigned opcode, unsigned flg, unsigned c10, unsigned rb, unsigned rd, unsigned cond)
{
	assert((opcode & ~0x7U) == 0);
	assert((flg & ~0x1U) == 0);
	assert((c10 & ~0x3FF) == 0);
	emit_u((opcode << 28) | (flg << 27) | (c10 << 16) | (rb << 8) | (rd << 4) | cond);
}

/* Emit an assembler error message to `stderr' */
static void
assembler_err(struct instr *instr, char *msg)
{
	fprintf(stderr, "ln %d: error: %s\n", instr->line, msg);
}

/* Return non-zero and emit error if `nd == NULL' */
static int
expect(struct instr *instr, struct value_nd *nd)
{
	if (!nd) {
		assembler_err(instr, "expected operand");
		return -1;
	}

	return 0;
}

/* Return non-zero and emit error if `nd != NULL' */
static int
dontexpect(struct instr *instr, struct value_nd *nd)
{
	if (nd) {
		assembler_err(instr, "too many operands");
		return -1;
	}

	return 0;
}

/* Return non-zero if `val' is not a register, but if it is, store its
 * register number in `reg'.
 * If force if set, also emit an error when returning non-zero.
 */
static int
expect_reg(struct instr *instr, struct value *val, unsigned *reg, int force)
{
	if (!val)
		return -1;

	if (val->kind != VK_REG) {
		if (force)
			assembler_err(instr, "expected register");
		return -1;
	}

	if (reg)
		*reg = val->val.reg;

	return 0;
}

/* Return non-zero if `val' is not an immediate constant or label, but if
 * it is, store its value in `imm'.
 * If force if set, also emit an error when returning non-zero.
 */
static int
expect_imm(struct instr *instr, struct value *val, unsigned *imm, int force)
{
	struct instr *label;

	if (!val)
		return -1;

	switch (val->kind) {
	case VK_IMM:
		if (imm)
			*imm = val->val.imm;
		break;
	case VK_LABEL:
		if (imm) {
			label = labels_get(val->val.label);
			if (!label) {
				assembler_err(instr, "label never declared");
				return -1;
			}
			*imm = label->addr_offset - instr->addr_offset;
		}
		break;
	default:
		if (force)
			assembler_err(instr, "expected immediate constant or label");
		return -1;
	}

	return 0;
}

/* Return non-zero if `val' is not a memory dereference, but if it is,
 * store the register part in `reg' and the immediate offset in `imm'.
 * If force if set, also emit an error when returning non-zero.
 */
static int
expect_mem(struct instr *instr, struct value *val, unsigned *reg, unsigned *imm, int force)
{
	if (!val)
		return -1;

	if (val->kind != VK_MEM) {
		if (force)
			assembler_err(instr, "expected memory location");
		return -1;
	}

	if (reg)
		*reg = val->val.mem.reg;

	expect_imm(instr, val->val.mem.offset, imm, 1);
	return 0;
}

/* Assemble a HALT instruction */
static int
assemble_halt(struct instr *instr)
{
	if (dontexpect(instr, instr->ops) < 0)
		return -1;

	emit_halt(instr->cond);
	return 0;
}

/* Assemble a READ instruction */
static int
assemble_read(struct instr *instr)
{
	unsigned c10, rd, ra;
	struct value_nd *fst, *snd;

	fst = instr->ops;
	if (expect(instr, fst) < 0 || expect_mem(instr, &fst->val, &ra, &c10, 1) < 0)
		return -1;

	snd = fst->next;
	if (expect(instr, snd) < 0 || expect_reg(instr, &snd->val, &rd, 1) < 0)
		return -1;

	if (dontexpect(instr, snd->next) < 0)
		return -1;

	emit_read(c10 & 0x3FF, ra, rd, instr->cond);
	return 0;
}

/* Assemble a WRITE instruction */
static int
assemble_write(struct instr *instr)
{
	unsigned c10, rb, ra;
	struct value_nd *fst, *snd;

	fst = instr->ops;
	if (expect(instr, fst) < 0 || expect_mem(instr, &fst->val, &ra, &c10, 1) < 0)
		return -1;

	snd = fst->next;
	if (expect(instr, snd) < 0 || expect_reg(instr, &snd->val, &rb, 1) < 0)
		return -1;

	if (dontexpect(instr, snd->next) < 0)
		return -1;

	emit_write(c10 & 0x3FF, rb, ra, instr->cond);
	return 0;
}

/* Assemble a PUSH instruction */
static int
assemble_push(struct instr *instr)
{
	unsigned ra;
	struct value_nd *fst;

	fst = instr->ops;
	if (expect(instr, fst) < 0 || expect_reg(instr, &fst->val, &ra, 1) < 0)
		return -1;

	if (dontexpect(instr, fst->next) < 0)
		return -1;

	emit_push(ra, instr->cond);
	return 0;
}

/* Assemble a POP instruction */
static int
assemble_pop(struct instr *instr)
{
	unsigned rd;
	struct value_nd *fst;

	fst = instr->ops;
	if (expect(instr, fst) < 0 || expect_reg(instr, &fst->val, &rd, 1) < 0)
		return -1;

	if (dontexpect(instr, fst->next) < 0)
		return -1;

	emit_pop(rd, instr->cond);
	return 0;
}

/* Assemble a LOADHI instruction */
static int
assemble_loadhi(struct instr *instr)
{
	unsigned c22, rd;
	struct value_nd *fst, *snd;

	fst = instr->ops;
	if (expect(instr, fst) < 0 || expect_imm(instr, &fst->val, &c22, 1) < 0)
		return -1;

	snd = fst->next;
	if (expect(instr, snd) < 0 || expect_reg(instr, &snd->val, &rd, 1) < 0)
		return -1;

	if (dontexpect(instr, snd->next) < 0)
		return -1;

	emit_loadhi(c22 & 0x3FFFFF, rd, instr->cond);
	return 0;
}

/* Assemble an ALU instruction */
static int
assemble_alu(struct instr *instr, unsigned opcode)
{
	int flg = toupper(instr->mnem[strlen(instr->mnem) - 1]) == 'F';
	unsigned c10, ra, rb, rd;
	struct value_nd *fst, *snd, *trd;

	fst = instr->ops;
	if (expect(instr, fst) < 0)
		return -1;

	expect_imm(instr, &fst->val, &c10, 0);
	expect_reg(instr, &fst->val, &ra, 0);

	snd = fst->next;
	if (expect(instr, snd) < 0 || expect_reg(instr, &snd->val, &rb, 1) < 0)
		return -1;

	trd = snd->next;
	if (expect(instr, trd) < 0 || expect_reg(instr, &trd->val, &rd, 1) < 0)
		return -1;

	switch (fst->val.kind) {
	case VK_REG:
		emit_arith_reg(opcode, flg, ra, rb, rd, instr->cond);
		break;
	case VK_IMM:
	case VK_LABEL:
		emit_arith_imm(opcode, flg, c10 & 0x3FF, rb, rd, instr->cond);
		break;
	default:
		assembler_err(instr, "expected register or immediate constant");
		return -1;
	}

	return 0;
}

static int
assemble_instr(struct instr *instr)
{
	if (!ci_strcmp(instr->mnem, "HALT"))
		return assemble_halt(instr);

	if (!ci_strcmp(instr->mnem, "READ"))
		return assemble_read(instr);

	if (!ci_strcmp(instr->mnem, "WRITE"))
		return assemble_write(instr);

	if (!ci_strcmp(instr->mnem, "PUSH"))
		return assemble_push(instr);

	if (!ci_strcmp(instr->mnem, "POP"))
		return assemble_pop(instr);

	if (!ci_strcmp(instr->mnem, "LOADHI"))
		return assemble_loadhi(instr);

	if (!ci_strcmp(instr->mnem, "OR") || !ci_strcmp(instr->mnem, "ORF"))
		return assemble_alu(instr, 0x0);

	if (!ci_strcmp(instr->mnem, "XOR") || !ci_strcmp(instr->mnem, "XORF"))
		return assemble_alu(instr, 0x1);

	if (!ci_strcmp(instr->mnem, "AND") || !ci_strcmp(instr->mnem, "ANDF"))
		return assemble_alu(instr, 0x2);

	if (!ci_strcmp(instr->mnem, "BIC") || !ci_strcmp(instr->mnem, "BICF"))
		return assemble_alu(instr, 0x3);

	if (!ci_strcmp(instr->mnem, "ROL") || !ci_strcmp(instr->mnem, "ROLF"))
		return assemble_alu(instr, 0x5);

	if (!ci_strcmp(instr->mnem, "ADD") || !ci_strcmp(instr->mnem, "ADDF"))
		return assemble_alu(instr, 0x6);

	if (!ci_strcmp(instr->mnem, "SUB") || !ci_strcmp(instr->mnem, "SUBF"))
		return assemble_alu(instr, 0x7);

	assembler_err(instr, "unknown instruction");
	return -1;
}

static int
assemble(void)
{
	struct instr_nd *ins;
	for (ins = first_instr; ins; ins = ins->next)
		if (assemble_instr(&ins->instr) < 0)
			return -1;
	return 0;
}


/*     _
 *  __| |___ __ _ _ _ _  _ _ __
 * / _| / -_) _` | ' \ || | '_ \
 * \__|_\___\__,_|_||_\_,_| .__/
 *                        |_|
 */

static void
cleanup_value(struct value *val)
{
	if (!val)
		return;

	if (val->kind == VK_MEM)
		cleanup_value(val->val.mem.offset);

	if (val->kind == VK_LABEL)
		free(val->val.label);
}

static void
cleanup_operands(struct value_nd *first)
{
	struct value_nd *nxt;
	while (first) {
		nxt = first->next;
		cleanup_value(&first->val);
		free(first);
		first = nxt;
	}
}

static void
cleanup_instrs(struct instr_nd *first)
{
	struct instr_nd *nxt;
	while (first) {
		nxt = first->next;
		free(first->instr.mnem);
		cleanup_operands(first->instr.ops);
		free(first);
		first = nxt;
	}
}

static void
cleanup_labels()
{
	struct label_kvp *kvp, *kvp_nxt;
	int i;

	for (i = 0; i < LABELS_HTABLE_MASK + 1; ++i) {
		kvp = labels[i];
		while (kvp) {
			kvp_nxt = kvp->next;
			free(kvp->label);
			free(kvp);
			kvp = kvp_nxt;
		}
	}
}

static void
cleanup(void)
{
	cleanup_instrs(first_instr);
	cleanup_labels();
}

int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "C");

	atexit(cleanup);

	if (parse() < 0)
		exit(1);

	if (assemble() < 0)
		exit(1);

	return 0;
}
