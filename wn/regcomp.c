/*
 * The files regcomp.c, regfind.c reg.h and regi.h are taken from the 
 * public domain editor "ve", written by Rico Tudor (rico@math.nwu.edu).
 * These regular expression routines were written by Henry Cejtin 
 * (henry@math.nwu.edu).  It is the desire of the authors that the
 * contents of these four files be placed in the public domain.
 */


/* 
 * regcomp.c
 *
 * This file contains all routines having to do with the regular expression
 * compiling.
 */

#include <stdlib.h>
#include "common.h"
#include "regi.h"
#include "reg.h"

#define	NQ	20			/* NFA allocation quantum */


/*
 * Local variables.
 */
static char		*nxtch;		/* next char in reg. exp. string */
static struct regprog	*prog;		/* current regprog */
static nfa		*nfanxt,	/* next slot in prog */
			*nfalim;	/* limit of prog */
static bool		pdone[MAXPAR];	/* iff `(' and `)' seen */


/*
 * Local functions.
 */
static bool	init(),			/* initialize for compile */
		compile(),		/* compile regular expression */
		comp1(),		/* compile paren-enclosed piece */
		makecls(),		/* make character class */
		addnst(),		/* add NFA state */
		addlp(),		/* add \( transition */
		addrp(),		/* add \) transition */
		adjust();		/* change prog size */
static void	cleanup(),		/* de-allocate after error */
		optimize();		/* optimize regprog */


/*
 * Regfree free()'s all space used by a compiled regular expression.
 */
void
regfree(rp)
struct regprog	*rp;
{
	register nfa	*np;

	for (np = rp->r_inst;; ++np)
		switch (np->n_comm.n_type) {
		case NMEW:
		case NMEOS:
		case NFINI:
			free((char *)rp);
			return;
		case NMCL:
			free((char *)np->n_mcl.n_cls);
			break;
		default:
			break;
		}
}


/*
 * Regcomp compiles a string which represents a regular expression into an
 * nfa.  It returns a pointer to the first transition (casted to a pointer
 * to a regprog).  If some problem occurs, it issues an error message and
 * returns NULL.
 */
struct regprog	*
regcomp(str)
char	*str;
{
	if (not init(str))
		return (NULL);
	if (not compile()) {
		cleanup();
		return (NULL);
	}
	optimize();
	return (prog);
}


/*
 * Init initializes all local variables to begin compiling the regular
 * expression contained in the string `str'.
 */
static bool
init(str)
char	*str;
{
	register unsigned	n;

	nxtch = str;
	n = sizeof(*prog) + NQ * sizeof(*prog->r_inst);
	prog = (struct regprog *)malloc(n);
	if (prog == NULL)
		return (FALSE);
	prog->r_npars = 0;
	prog->r_anchor = RANY;
	nfanxt = prog->r_inst;
	nfalim = &nfanxt[NQ];
	for (n=0; n != MAXPAR; ++n)
		pdone[n] = FALSE;
	return (TRUE);
}


/*
 * Compile a regular expression.
 */
static bool
compile()
{
	switch (*nxtch) {
	case '^':
		prog->r_anchor = RBOS;
		++nxtch;
		break;
#if 0 /* non-standard regexp character */
	case '~':
		prog->r_anchor = RBOW;
		++nxtch;
		break;
#endif
	}
	if (not comp1())
		return (FALSE);
	switch (*nxtch) {
	case '$':
		if (*++nxtch != EOS)
			return (FALSE);
		if (not addnst(NMEOS))
			return (FALSE);
		break;
#if 0 /* non-standard regexp character */
	case '~':
		if (*++nxtch != EOS)
			return (FALSE);
		if (not addnst(NMEW))
			return (FALSE);
		break;
#endif
	case EOS:
		if (not addnst(NFINI))
			return (FALSE);
		break;
	default:
		return (FALSE);
	}
	return (adjust(nfanxt - prog->r_inst));
}


/*
 * Comp1 compiles a regular expression with an assumed left and
 * right parenthesis surrounding the entire expression.  It recursively
 * calls itself for parenthesized sub-expressions.  When it returns TRUE
 * (indicating all is ok), the next character will either be EOS, `$' or
 * `\)'.
 */
static bool
comp1()
{
	register int	ch;
	register bool	clsok;
	int		level;

	if (not addlp(&level))
		return (FALSE);
	clsok = FALSE;
	loop
		switch (ch = *nxtch++) {
		case EOS:
			--nxtch;
			return (addrp(level));
		case '^':
			return (FALSE);
		case '$':
#if 0 /* non-standard regexp character */
		case '~':
#endif
			--nxtch;
			return (addrp(level));
		case '*':
			if (not clsok)
				return (FALSE);
			if (not addnst(NCLO))
				return (FALSE);
			nfanxt[-1] = nfanxt[-2];
			nfanxt[-2].n_comm.n_type = NCLO;
			clsok = FALSE;
			break;
		case '.':
			if (not addnst(NMANY))
				return (FALSE);
			clsok = TRUE;
			break;
		case '[':
			if ((not addnst(NMCL))
			or  (not makecls(&nfanxt[-1].n_mcl.n_cls)))
				return (FALSE);
			clsok = TRUE;
			break;
		case '\\':
			switch (ch = *nxtch++) {
			case EOS:
				return (FALSE);
			case '(':
				if (not comp1())
					return (FALSE);
				if (*nxtch++ != '\\' || *nxtch++ != ')')
					return (FALSE);
				clsok = FALSE;
				break;
			case ')':
				nxtch -= 2;
				return (addrp(level));
			default:
				if ('1' <= ch && ch <= '9') {
					ch -= '0';
					if (not pdone[ch])
						return (FALSE);
					if (not addnst(NMSUBS))
						return (FALSE);
					nfanxt[-1].n_msubs.n_indx = 2*ch;
					clsok = FALSE;
				} else {
					if (not addnst(NMCH))
						return (FALSE);
					nfanxt[-1].n_mch.n_char = ch;
					clsok = TRUE;
				}
				break;
			}
			break;
		default:
			if (not addnst(NMCH))
				return (FALSE);
			nfanxt[-1].n_mch.n_char = ch;
			clsok = TRUE;
			break;
		}
}


/*
 * Makecls makes a character class.
 */
static bool
makecls(cpp)
char	**cpp;
{
	register char	*cp;
	register int	ch,
			n;
	bool		negate;

	*cpp = cp = (char *)malloc(CVECL * sizeof(*cp));
	if (cp == NULL)
		return (FALSE);
	for (n=0; n != CVECL; ++n)
		cp[n] = 0;
	negate = FALSE;
	if (*nxtch == '^') {
		++nxtch;
		negate = TRUE;
	}
	loop {
		ch = *nxtch++;
		switch (ch) {
		case '\\':
			ch = *nxtch++;
			if (ch == EOS)
				return (FALSE);
			break;
		case EOS:
			return (FALSE);
		case ']':
			if (negate) {
				for (n=0; n != CVECL; ++n)
					cp[n] = ~cp[n];
				cp[EOS/BPC] &= ~ (1 << EOS%BPC);
			}
			return (TRUE);
		}
		ch = (unsigned)ch % CSIZE;
		n = ch;
		if (*nxtch == '-') {
			++nxtch;
			ch = *nxtch++;
			switch (ch) {
			case '\\':
				ch = *nxtch++;
				if (ch == EOS)
					return (FALSE);
				break;
			case EOS:
				return (FALSE);
			}
			ch = (unsigned)ch % CSIZE;
			if (n > ch)
				return (FALSE);
		}
		do {
			cp[n/BPC] |= 1 << n%BPC;
		} while (n++ != ch);
	}
}


/*
 * Addnst adds an nfa transition.
 */
static bool
addnst(type)
int	type;
{
	if ((nfanxt == nfalim)
	and (not adjust(nfalim - prog->r_inst + NQ)))
		return (FALSE);
	nfanxt++->n_comm.n_type = type;
	return (TRUE);
}


/*
 * Addlp adds a left-parenthesis transition, and sets the integer pointed
 * to by `pnp' to the parnthesis level.
 */
static bool
addlp(pnp)
int	*pnp;
{
	register int	pc;

	pc = prog->r_npars++;
	if (pc >= MAXPAR)
		return (FALSE);
	*pnp = pc;
	if (not addnst(NSAVE))
		return (FALSE);
	nfanxt[-1].n_save.n_indx = 2*pc;
	return (TRUE);
}


/*
 * Addrp adds a right-parenthesis transition for parenthesis number `pn'.
 */
static bool
addrp(pn)
register int	pn;
{
	assert(pn < MAXPAR);
	if (not addnst(NSAVE))
		return (FALSE);
	pdone[pn] = TRUE;
	nfanxt[-1].n_save.n_indx = 2*pn + 1;
	return (TRUE);
}


/*
 * Adjust the size of prog.
 */
static bool
adjust(nlen)
register unsigned	nlen;
{
	register unsigned	olen,
			nsize;

	olen = nfanxt - prog->r_inst;
	nsize = sizeof(*prog) + nlen*sizeof(*prog->r_inst);
	prog = (struct regprog *)realloc(prog, nsize);
	if (prog == NULL)
		return (FALSE);	/* character class memory lost */
	nfanxt = &prog->r_inst[olen];
	nfalim = &prog->r_inst[nlen];
	return (TRUE);
}


/*
 * Cleanup de-allocates anything allocated in case an error is detected.
 */
static void
cleanup()
{
	register nfa	*np;

	if (prog == NULL)
		return;
	for (np = prog->r_inst; np != nfanxt; ++np)
		if ((np->n_comm.n_type == NMCL)
		and (np->n_mcl.n_cls != NULL))
			free((char *)np->n_mcl.n_cls);
	free((char *)prog);
}


/*
 * Optimize is used to speed up matches by noting what any match must start
 * with.
 */
static void
optimize()
{
	register nfa	*np;

	for (np = prog->r_inst; np->n_comm.n_type == NSAVE; ++np)
		;
	if ((np[0].n_comm.n_type == NCLO)
	and (np[1].n_comm.n_type == NMANY))
		prog->r_anchor = RBOS;	/* /.*junk/ can only match at start */
	prog->r_start = np;
}
