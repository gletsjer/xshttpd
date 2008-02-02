/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdarg.h>
#include	<errno.h>

#ifndef		HAVE_ERR_H
void
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

void
errx(int code, const char *format, ...)
{
	va_list		ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(code);
}

void
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

void
warnx(const char *format, ...)
{
	va_list		ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
#endif		/* HAVE_ERR_H */
