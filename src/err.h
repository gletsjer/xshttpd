/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HAVE_STRERROR
const char *	strerror		(int);
#endif		/* HAVE_STRERROR */

void	err			(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	errx			(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	warn			(const char *, ...) PRINTF_LIKE(1, 2);
void	warnx			(const char *, ...) PRINTF_LIKE(1, 2);
