/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
#ifdef		HAVE_SETPROCTITLE
#define setprocname	setproctitle
#else		/* Not HAVE_SETPROCTITLE */
extern	VOID	setprocname		PROTO((const char *, ...));
#endif		/* HAVE_SETPROCTITLE */
extern	VOID	initsetprocname		PROTO((int, char **, char**));
#endif		/* NOFORWARDS */
