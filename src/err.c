/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: err.c,v 1.4 2004/11/26 16:45:09 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#ifdef		NONEWSTYLE
#include	<varargs.h>
#else		/* Not NONEWSTYLE */
#include	<stdarg.h>
#endif		/* NONEWSTYLE */
#include	<errno.h>


#ifndef		HAVE_ERR_H
#ifndef		NONEWSTYLE
extern	void
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

extern	void
errx(int code, const char *format, ...)
{
	va_list		ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(code);
}

extern	void
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
extern	void
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

extern	void
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

extern	void
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
