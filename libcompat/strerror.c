/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: strerror.c,v 1.1 2006/12/17 13:29:44 johans Exp $ */

#include	"config.h"

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
