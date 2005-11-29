/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */
/* $Id: pcre.c,v 1.3 2005/11/29 18:16:28 johans Exp $ */

#include	"config.h"
#include	"pcre.h"

#include	<stdio.h>
#include	<string.h>
#ifdef		HAVE_PCRE_H
#include	<pcre.h>
#else		/* HAVE_PCRE_H */
#ifdef		HAVE_PCRE_PCRE_H
#include	<pcre/pcre.h>
#endif		/* HAVE_PCRE_PCRE_H */
#endif		/* HAVE_PCRE_H */

char *
pcre_subst(const char * const string, const char * const pattern, const char * const replacement)
{
	int		erroffset, rc, ovector[OVSIZE];
	char		*result;
	const char	*error, *prev, *next, **list;
	pcre 		*re;

	if (!(re = pcre_compile(pattern, 0, &error, &erroffset, NULL)))
		return NULL;

	rc = pcre_exec(re, NULL, string, strlen(string), 0, 0, ovector, OVSIZE);

	if (rc <= 0)
		return NULL;

	result = malloc(BUFSIZ);
	result[0] = '\0';
	strncat(result, string, ovector[0]);
	pcre_get_substring_list(string, ovector, rc, &list);
	for (prev = replacement; (next = strchr(prev, '\\')); prev = next + 2)
	{
		int	loc = next[1] - '0';
		if (loc < 0 || loc > 9 || loc >= rc)
			continue;
		if (next > prev && strlen(result) + (next - prev) < BUFSIZ)
			strncat(result, prev, next - prev);
		strlcat(result, list[loc], BUFSIZ);
	}
	strlcat(result, prev, BUFSIZ);
	strlcat(result, &string[ovector[1]], BUFSIZ);

	return result;
}

#if	0
int
main(void)
{
	char	*subst = pcre_subst("fiets", "(i)", "\\1e\\0");
	if (subst)
		puts(subst);
	return 0;
}
#endif
