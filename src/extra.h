/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		EXTRA_H
#define		EXTRA_H

#include	"htconfig.h"

struct tm *	localtimenow	(void) WARNUNUSED;
char *	gmtimestamp		(void) WARNUNUSED;
bool	mysleep			(int);
bool	match			(const char *, const char *) NONNULL WARNUNUSED;
bool	match_list		(char *, const char *) NONNULL WARNUNUSED;
size_t	string_to_array		(const char *, char **) NONNULL1;	/* prealloced */
size_t	string_to_arrayp	(const char *, char ***) NONNULL1;	/* malloc()s */
size_t	string_to_arraypn	(const char *, char ***) NONNULL1;	/* malloc() + 0-terminates */
size_t	qstring_to_array	(const char *, char **) NONNULL1;	/* ;q-value strings */
size_t	qstring_to_arrayp	(const char *, char ***) NONNULL1;
size_t	qstring_to_arraypn	(const char *, char ***) NONNULL1;
size_t	eqstring_to_array	(char *, struct mapping *) NONNULL1;	/* idx=val strings */
void	free_string_array	(char **, size_t);
void	free_string_arrayp	(char **);

#endif		/* EXTRA_H */
