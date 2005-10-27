/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

int	mysleep			(int);
#ifndef		HAVE_KILLPG
int	killpg			(pid_t, int);
#endif		/* HAVE_KILLPG */

int	match			(const char *, const char *);
int	match_list		(char *, const char *);

#ifdef		HAVE_GETOPT_H
#include	<getopt.h>
#endif		/* HAVE_GETOPT_H */

#if		!HAVE_DECL_OPTARG
extern	char	*optarg;
extern	int	optind;
#endif		/* HAVE_DECL_OPTARG */
