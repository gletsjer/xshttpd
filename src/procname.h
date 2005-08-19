/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifdef		HAVE_SETPROCTITLE
#define setprocname	setproctitle
#else		/* Not HAVE_SETPROCTITLE */
void	setprocname		(const char *, ...) PRINTF_LIKE(1, 2);
#endif		/* HAVE_SETPROCTITLE */
void	initsetprocname		(int, char **);
