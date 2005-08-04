/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifdef		HAVE_GETOPT_H
#include	<getopt.h>
#endif		/* HAVE_GETOPT_H */

#if		!HAVE_DECL_OPTARG
extern	char	*optarg;
extern	int	optind;
#endif		/* HAVE_DECL_OPTARG */
