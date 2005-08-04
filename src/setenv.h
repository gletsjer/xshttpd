/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HAVE_SETENV
char	*getenv		(const char *);
int	setenv		(const char *, const char *, int);
void	unsetenv	(const char *);
#endif		/* HAVE_SETENV */

#if		!HAVE_DECL_ENVIRON
extern	char	**environ;
#endif		/* HAVE_DECL_ENVIRON */
