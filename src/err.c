/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: err.c,v 1.5 2004/11/26 17:17:27 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdarg.h>
#include	<errno.h>


#ifndef		HAVE_ERR_H
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
#endif		/* HAVE_ERR_H */
