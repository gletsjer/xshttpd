/* Copyright (C) 2007-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	<sys/types.h>
#include	<unistd.h>
#ifdef		HAVE_SETRLIMIT
#include	<sys/time.h>
#include	<sys/resource.h>
#endif		/* HAVE_SETRLIMIT */

int
closefrom(int fd)
{
#ifdef          HAVE_SETRLIMIT
	struct rlimit	limits;
	rlim_t		count;

	getrlimit(RLIMIT_NOFILE, &limits);
	for (count = fd; count < limits.rlim_max; count++)
		(void) close(count);

#else           /* HAVE_SETRLIMIT */
	int		count;

	for (count = fd; count < 1024; count++)
		(void) close(count);
#endif          /* HAVE_SETRLIMIT */
	return 0;
}
