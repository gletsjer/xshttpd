/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		PCRE_H
#define		PCRE_H

#include	"config.h"

#define		OVSIZE	30	/* allows \0 through \9 */

char *pcre_subst(const char * const, const char * const, const char * const) MALLOC_FUNC NONNULL;
int pcre_match(const char * const, const char * const) NONNULL WARNUNUSED;

#endif		/* PCRE_H */
