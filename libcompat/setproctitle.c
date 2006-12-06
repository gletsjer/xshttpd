/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: setproctitle.c,v 1.4 2006/12/06 20:56:56 johans Exp $ */

#include	"config.h"

#ifdef		HAVE_SYS_EXEC_H
#endif		/* HAVE_SYS_EXEC_H */
#ifdef		HAVE_SYS_PARAM_H
#include	<sys/param.h>
#endif		/* HAVE_SYS_PARAM_H */
#ifdef		HAVE_SYS_PSTAT_H
#include	<sys/pstat.h>
#endif		/* HAVE_SYS_PSTAT_H */
#ifdef		HAVE_SYS_SYSMIPS_H
#include	<sys/sysmips.h>
#endif		/* HAVE_SYS_SYSMIPS_H */
#ifdef		HAVE_SYS_SYSNEWS_H
#include	<sys/sysnews.h>
#endif		/* HAVE_SYS_SYSNEWS_H */

#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<err.h>
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */

#include	"setproctitle.h"

static	char	*procnamestart, *procnameend;

void
setproctitle(const char *name, ...)
{
	va_list		ap;
	static	char	buffer[256];
#ifdef 		PS_STRINGS
	static	char	*argv;
#endif		/* PS_STRINGS */

	va_start(ap, name);

	vsnprintf(buffer, 256, name, ap);
	va_end(ap);

#ifdef		PS_STRINGS
	PS_STRINGS->ps_nargvstr = 1;
	argv = buffer;
	PS_STRINGS->ps_argvstr = &argv;
#else		/* Not PS_STRINGS */
#ifdef		PSTAT_SETCMD
	{
		union	pstun	pst;

		pst.pst_command = buffer;
		pstat(PSTAT_SETCMD, pst, strlen(buffer), 0, 0);
	}
#else		/* Not HAVE_PSTAT_SETCMD */
#ifdef		SONY_SYSNEWS
	sysmips(SONY_SYSNEWS, NEWS_SETPSARGS, buffer);
#else		/* Not SONY_SYSNEWS */
	{
		int			len;
		char		*p;

		len = strlen(buffer);
		if (len > procnameend - procnamestart - 2)
		{
			len = procnameend - procnamestart - 2;
			buffer[len] = 0;
		}
		strlcpy(procnamestart, buffer, 256);
		p = procnamestart + len;
		while (p < procnameend)
			*(p++) = '\0';
	}
#endif		/* SONY_SYSNEWS */
#endif		/* PSTAT_SETCMD */
#endif		/* PS_STRINGS */
}

void
initproctitle(int argc, char **argv)
{
#ifndef		PS_STRINGS
	procnameend = argv[argc - 1] + strlen(argv[argc - 1]);
	procnamestart = argv[0];
	argv[1] = NULL;
	setproctitle("xs: Process name initialized...");
#else		/* Not PS_STRINGS */
	procnamestart = procnameend = NULL;
#endif		/* PS_STRINGS */
}
