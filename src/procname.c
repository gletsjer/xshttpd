/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#ifdef		HAVE_SYS_EXEC_H
#include	<sys/exec.h>
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

#ifdef		HAVE_MACHINE_VMPARAM_H
#include	<vm/pmap.h>
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
#include	"string.h"

#ifdef		NEED_DECL_ENVIRON
extern	char	**environ;
#endif		/* NEED_DECL_ENVIRON */

static	char	*procnamestart, *procnameend;

#ifndef		NONEWSTYLE
extern	VOID
setprocname(const char *name, ...)
{
	va_list		ap;
	static	char	buffer[256], *argv;

	va_start(ap, name);
#else		/* Not not NONEWSTYLE */
extern	VOID
setprocname(name, va_alist)
const	char	*name;
va_dcl
{
	va_list		ap;
	static	char	buffer[256], *argv;

	va_start(ap);
#endif		/* NONEWSTYLE */

	vsprintf(buffer, name, ap);
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
		size_t		len;
		char		*p;

		len = strlen(buffer);
		if (len > procnameend - procnamestart - 2)
		{
			len = procnameend - procnamestart - 2;
			buffer[len] = 0;
		}
		strcpy(procnamestart, buffer);
		p = procnamestart + len;
		while (p < procnameend)
			*(p++) = ' ';
	}
#endif		/* SONY_SYSNEWS */
#endif		/* PSTAT_SETCMD */
#endif		/* PS_STRINGS */
}

extern	VOID
initsetprocname DECL3(int, argc, char **, argv, char **, envp)
{
#ifndef		PS_STRINGS
	int		i, len;

	for (i = 0; envp[i]; i++)
		/* NOTHING HERE */;
	environ = (char **)malloc(sizeof(char *) * (i + 1));
	for (i = 0; envp[i]; i++)
	{
		len = strlen(envp[i]);
		environ[i] = (char *)malloc(len + 1);
		bcopy(envp[i], environ[i], len + 1);
	}
	environ[i] = NULL;
	if (i > 0)
		procnameend = envp[i - 1] + strlen(envp[i - 1]);
	else
		procnameend = argv[argc - 1] + strlen(argv[argc - 1]);
	procnamestart = argv[0];
	argv[1] = NULL;
	setprocname("xs: Process name initialized...");
#else		/* Not PS_STRINGS */
	procnamestart = procnameend = NULL;
#endif		/* PS_STRINGS */
}
