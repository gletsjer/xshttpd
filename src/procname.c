/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: procname.c,v 1.12 2004/11/26 16:45:09 johans Exp $ */

#include	"config.h"

#ifdef		HAVE_SYS_EXEC_H
#endif		/* HAVE_SYS_EXEC_H */
#ifdef		HAVE_SYS_PARAM_H
#include	<sys/param.h>
#endif		/* HAVE_SYS_PARAM_H */
#ifdef		HAVE_SYS_PSTAT_H
/* This is stupid but keeps the warnings away */
struct		pst_status;
struct		pst_dynamic;
struct		pst_static;
struct		pst_vminfo;
struct		pst_diskinfo;
struct		pst_processor;
struct		pst_lv;
struct		pst_swapinfo;
#include	<sys/pstat.h>
#endif		/* HAVE_SYS_PSTAT_H */
#ifdef		HAVE_SYS_SYSMIPS_H
#include	<sys/sysmips.h>
#endif		/* HAVE_SYS_SYSMIPS_H */
#ifdef		HAVE_SYS_SYSNEWS_H
#include	<sys/sysnews.h>
#endif		/* HAVE_SYS_SYSNEWS_H */

#ifdef		HAVE_VM_VM_H
#include	<vm/vm.h>
#endif		/* HAVE_VM_VM_H */

#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */
#ifdef		HAVE_VM_PMAP_H
#include	<vm/pmap.h>
#endif		/* HAVE_VM_PMAP_H */
#ifdef		HAVE_MACHINE_VMPARAM_H
#include	<machine/vmparam.h>
#endif		/* HAVE_MACHINE_VMPARAM_H */

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#ifndef		NONEWSTYLE
#include	<stdarg.h>
#else		/* Not not NONEWSTYLE */
#include	<varargs.h>
#endif		/* NONEWSTYLE */
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */

#include	"procname.h"

#ifdef		NEED_DECL_ENVIRON
extern	char	**environ;
#endif		/* NEED_DECL_ENVIRON */

static	char	*procnamestart, *procnameend;

#ifndef		HAVE_SETPROCTITLE
#ifndef		NONEWSTYLE
extern	void
setprocname(const char *name, ...)
{
	va_list		ap;
	static	char	buffer[256];
#ifdef 		PS_STRINGS
	static	char	*argv;
#endif		/* PS_STRINGS */

	va_start(ap, name);
#else		/* Not not NONEWSTYLE */
extern	void
setprocname(name, va_alist)
const	char	*name;
va_dcl
{
	va_list		ap;
	static	char	buffer[256], *argv;

	va_start(ap);
#endif		/* NONEWSTYLE */

	vsnprintf(buffer, 256, name, ap);
	buffer[255] = '\0';
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
		strncpy(procnamestart, buffer, 256);
		p = procnamestart + len;
		while (p < procnameend)
			*(p++) = '\0';
	}
#endif		/* SONY_SYSNEWS */
#endif		/* PSTAT_SETCMD */
#endif		/* PS_STRINGS */
}
#endif		/* HAVE_SETPROCTITLE */

extern	void
initsetprocname(int argc, char **argv, char **envp)
{
#ifndef		PS_STRINGS
	/* start with empty environment */
	environ = (char **)malloc(sizeof(char *));
	*environ = NULL;

	procnameend = argv[argc - 1] + strlen(argv[argc - 1]);
	procnamestart = argv[0];
	argv[1] = NULL;
	setprocname("xs: Process name initialized...");
#else		/* Not PS_STRINGS */
	procnamestart = procnameend = NULL;
#endif		/* PS_STRINGS */
	(void) envp;	/* unused */
}
