/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		EXTRA_H
#define		EXTRA_H

#include	"htconfig.h"

int	mysleep			(int);
int	match			(const char *, const char *);
int	match_list		(char *, const char *);
size_t	string_to_array		(char *, char **);	/* prealloced */
size_t	string_to_arrayp	(char *, char ***);	/* malloc()s */
size_t	string_to_arraypn	(char *, char ***);	/* malloc() + 0-terminates */
size_t	qstring_to_array	(char *, char **);	/* ;q-value strings */
size_t	qstring_to_arrayp	(char *, char ***);
size_t	qstring_to_arraypn	(char *, char ***);
size_t	eqstring_to_array	(char *, struct mapping *);	/* idx=val strings */
uid_t	valid_user		(const char *);

#endif		/* EXTRA_H */
