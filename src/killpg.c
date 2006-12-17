/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: killpg.c,v 1.1 2006/12/17 13:29:44 johans Exp $ */

#include	<sys/types.h>
#include	<signal.h>
#include	<unistd.h>

int
killpg(pid_t process, int sig)
{
	if (!process)
		process = getpid();
	return (kill(-process, sig));
}
