/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

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
