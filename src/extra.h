/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	<sys/types.h>

int	mysleep			(int);

int	match			(const char *, const char *);
int	match_list		(char *, const char *);
uid_t	valid_user		(const char *);

#ifdef		HAVE_GETOPT_H
#include	<getopt.h>
#endif		/* HAVE_GETOPT_H */
