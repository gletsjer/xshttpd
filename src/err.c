/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#ifdef		NONEWSTYLE
#include	<varargs.h>
#else		/* Not NONEWSTYLE */
#include	<stdarg.h>
#endif		/* NONEWSTYLE */
#include	<errno.h>

#include	"string.h"

#ifndef		HAVE_ERR_H
#ifndef		NONEWSTYLE
extern	VOID
err(int code, const char *format, ...)
{
	va_list		ap;
	int		olderrno;

	olderrno = errno;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(olderrno));
	exit(code);
}

extern	VOID
errx(int code, const char *format, ...)
{
	va_list		ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(code);
}

extern	VOID
warn(const char *format, ...)
{
	va_list		ap;
	int		olderrno;

	olderrno = errno;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(olderrno));
	errno = olderrno;
}
#else		/* Not not NONEWSTYLE */
extern	VOID
err(code, format, va_alist)
int		code;
const	char	*format;
va_dcl
{
	va_list		ap;
	int		olderrno;

	olderrno = errno;
	va_start(ap);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(olderrno));
	exit(code);
}

extern	VOID
errx(code, format, va_alist)
int		code;
const	char	*format;
va_dcl
{
	va_list		ap;

	va_start(ap);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(code);
}

extern	VOID
warn(format, va_alist)
const	char	*format;
va_dcl
{
	va_list		ap;
	int		olderrno;

	olderrno = errno;
	va_start(ap);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(olderrno));
	errno = olderrno;
}

#endif		/* NONEWSTYLE */
#endif		/* HAVE_ERR_H */
