/* Copyright (C) 2005-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#ifdef		HAVE_PCRE
#include	<pcre.h>
#endif		/* HAVE_PCRE */

#include	"pcre.h"
#include	"malloc.h"

char *
pcre_subst(const char * const string, const char * const pattern, const char * const replacement)
{
#ifndef		HAVE_PCRE
	char		*result;
	const char	*match = strcasestr(string, pattern);

	/* no pcre -> no substitute */
	if (!match)
		return NULL;

	ASPRINTF(&result, "%.*s%s%s", (int)(match - string), string,
		replacement, match + strlen(pattern));

	return result;
#else		/* Not Not HAVE_PCRE */
	int		erroffset, rc, ovector[OVSIZE];
	char		*result;
	const char	*error, *prev, *next, **list;
	pcre 		*re;

	if (!(re = pcre_compile(pattern, 0, &error, &erroffset, NULL)))
		return NULL;

	rc = pcre_exec(re, NULL, string, strlen(string), 0, 0, ovector, OVSIZE);
	pcre_free(re);

	if (rc <= 0)
		return NULL;

	MALLOC(result, char, BUFSIZ);
	result[0] = '\0';
	if (!strstr(replacement, "://"))
		/* redirect to local path: subst on original url */
		strncat(result, string, ovector[0]);
	pcre_get_substring_list(string, ovector, rc, &list);
	for (prev = replacement; (next = strchr(prev, '\\')); prev = next + 2)
	{
		const size_t	len = next - prev;
		const int	loc = next[1] - '0';

		if (loc < 0 || loc > 9 || loc >= rc)
			continue;
		if (next > prev && strlen(result) + len < BUFSIZ)
			strncat(result, prev, len);
		strlcat(result, list[loc], BUFSIZ);
	}
	strlcat(result, prev, BUFSIZ);
	strlcat(result, &string[ovector[1]], BUFSIZ);

	return result;
#endif		/* HAVE_PCRE */
}

/* checks whether [string] matches [pattern]. returns:
 * -1 : PCRE error
 *  0 : no match
 *  1 : match
 */
int
pcre_match(const char *const string, const char *const pattern)
{
#ifndef		HAVE_PCRE
	/* no pcre -> litteral string match */
	return strcasestr(string, pattern) ? 1 : 0;
#else		/* Not Not HAVE_PCRE */
	int		erroffset, rc;
	const char	*error;
	pcre		*re;

	if (!(re = pcre_compile(pattern, 0, &error, &erroffset, NULL)))
		return -1;

	rc = pcre_exec(re, NULL, string, strlen(string), 0, 0, NULL, 0);
	pcre_free(re);
	if (PCRE_ERROR_NOMATCH == rc)
		return 0;
	return rc < 0 ? -1 : 1;
#endif		/* HAVE_PCRE */
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
