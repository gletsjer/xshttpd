/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

int	mysleep			(int);

int	match			(const char *, const char *);
int	match_list		(char *, const char *);

#ifdef		HAVE_GETOPT_H
#include	<getopt.h>
#endif		/* HAVE_GETOPT_H */
