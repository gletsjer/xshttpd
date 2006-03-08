/* Copyright (C) 2006 by Johan van Selst (johans@stack.nl) */
/* $Id: reformatxs.c,v 1.4 2006/03/08 17:23:40 johans Exp $ */

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
main(void)
{
	int		num, fdin, fdout;
	countold	ocounter;
	countstr	counter;
	char		counterfile[XS_PATH_MAX], lockfile[XS_PATH_MAX];
	char		xscount_version;

	snprintf(counterfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_DATA);
	if ((fdin  = open(counterfile, O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	if (read(fdin, &xscount_version, sizeof(char)) != sizeof(char))
		err(1, "Could not read(%s)", counterfile);

	if (XSCOUNT_VERSION == xscount_version)
		errx(2, "Conversion not needed: file has current version");

	if (xscount_version <= 0 || xscount_version > XSCOUNT_VERSION)
		errx(1, "Cannot convert data: corrupt or unknown version");

	if (lseek(fdin, (off_t)0, SEEK_SET) < 0)
		err(1, "lseek()");

	snprintf(lockfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_LOCK);
	if ((fdout = open(lockfile, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
		err(1, "Could not open(%s)", lockfile);

	num = 0;
	while (read(fdin, &ocounter, sizeof(countold)) == sizeof(countold))
	{
		memcpy(counter.filename, ocounter.filename, 128);
		counter.total = ocounter.total;
		counter.month = ocounter.month;
		counter.today = ocounter.today;
		counter.lastseen = (time_t)0;
		if (!num++)
			counter.filename[0] = XSCOUNT_VERSION;
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
	printf("Successfully converted %d records\n", num);
	return(0);
}
