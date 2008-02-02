/* Copyright (C) 2007-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	<sys/time.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<unistd.h>

void
srandomdev()
{
	int		fd;
	unsigned long	seed;

	if ((fd = open("/dev/random", O_RDONLY, 0)) < 0 ||
		read(fd, &seed, sizeof(seed) != sizeof(seed)))
	{
		struct timeval	tv;
		unsigned long	junk;

		gettimeofday(&tv, NULL);
		srandom(getpid() ^ tv.tv_sec ^ tv.tv_usec ^ junk);
		return;
	}
	srandom(seed);
}
