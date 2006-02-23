/* Copyright (C) 2006 by Johan van Selst (johans@stack.nl) */
/* $Id: reformatxs.c,v 1.1 2006/02/23 16:25:08 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<string.h>
#include	<signal.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */
#include	<pwd.h>

#include	"xscounter.h"

typedef	struct	countold
{
	char	filename[128];
	int	total, month, today;
} countold;

int
main(int argc, char **argv)
{
	int		option, fdin, fdout;
	countold	ocounter;
	countstr	counter;
	char		counterfile[XS_PATH_MAX], lockfile[XS_PATH_MAX];
	struct tm	timeptr;
	time_t		since = 0;

	snprintf(counterfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_DATA);
	if ((fdin  = open(counterfile, O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	snprintf(lockfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_LOCK);
	if ((fdout = open(lockfile, O_WRONLY | O_CREAT | O_TRUNC, 0)) < 0)
		err(1, "Could not open(%s)", lockfile);

	while (read(fdin, &ocounter, sizeof(countold)) == sizeof(countold))
	{
		strlcpy(counter.filename, ocounter.filename, 128);
		counter.total = ocounter.total;
		counter.month = ocounter.month;
		counter.today = ocounter.today;
		counter.lastseen = (time_t)0;
		if (write(fdout, &counter, sizeof(countstr)) !=sizeof(countstr))
			err(1, "write()");
	}
	close(fdin); close(fdout);
	if (rename(lockfile, counterfile))
	{
		remove(lockfile);
		err(1, "Could not rename counter file");
	}
	remove(lockfile);
	return(0);
}
