/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: err.c,v 1.7 2005/10/27 19:15:01 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdarg.h>
#include	<errno.h>

#ifndef		HAVE_STRERROR

#if		!HAVE_DECL_SYS_ERRLIST
extern	char		*sys_errlist[];
extern	const	int	sys_nerr;
#endif		/* HAVE_DECL_SYS_ERRLIST */

const	char	*
strerror(int code)
{
	if ((code < 0) || (code > sys_nerr))
		return("Undefined error");
	else
		return(sys_errlist[code]);
}
#endif		/* HAVE_STRERROR */

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
#endif		/* HAVE_ERR_H */
