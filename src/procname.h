/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifdef		HAVE_SETPROCTITLE
#define setprocname	setproctitle
#else		/* Not HAVE_SETPROCTITLE */
void	setprocname		(const char *, ...);
#endif		/* HAVE_SETPROCTITLE */
void	initsetprocname		(int, char **);
