/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		EXTRA_H
#define		EXTRA_H

#include	"htconfig.h"

int	mysleep			(int);
int	match			(const char *, const char *);
int	match_list		(char *, const char *);
size_t	string_to_array		(char *, char **);
size_t	string_to_arrayp	(char *, char ***);
size_t	eqstring_to_array	(char *, struct mapping *);
uid_t	valid_user		(const char *);

#endif		/* EXTRA_H */
