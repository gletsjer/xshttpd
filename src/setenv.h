/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HAVE_SETENV
#ifndef		NOFORWARDS
extern	char	*getenv		PROTO((const char *));
extern	int	setenv		PROTO((const char *, const char *, int));
extern	VOID	unsetenv	PROTO((const char *));
#endif		/* NOFORWARDS */
#endif		/* HAVE_SETENV */
