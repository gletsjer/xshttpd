/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HAVE_SETENV
#ifndef		NOFORWARDS
extern	char	*getenv		(const char *);
extern	int	setenv		(const char *, const char *, int);
extern	void	unsetenv	(const char *);
#endif		/* NOFORWARDS */
#endif		/* HAVE_SETENV */

#ifdef		NEED_DECL_ENVIRON
extern	char	**environ;
#endif		/* NEED_DECL_ENVIRON */
