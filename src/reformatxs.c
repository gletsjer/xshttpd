/* Copyright (C) 2006 by Johan van Selst (johans@stack.nl) */
/* $Id: reformatxs.c,v 1.5 2006/05/10 15:28:24 johans Exp $ */

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
#define		CNT_SZ		sizeof(countstr)

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
	countstr	counter, counter_prev;
	char		counterfile[XS_PATH_MAX], lockfile[XS_PATH_MAX];
	char		xscount_version;

	snprintf(counterfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_DATA);
	if ((fdin  = open(counterfile, O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	if (read(fdin, &xscount_version, sizeof(char)) != sizeof(char))
		err(1, "Could not read(%s)", counterfile);

	if (xscount_version <= 0 || xscount_version > XSCOUNT_VERSION)
		errx(1, "Cannot convert data: corrupt or unknown version");

	if (lseek(fdin, (off_t)0, SEEK_SET) < 0)
		err(1, "lseek()");

	snprintf(lockfile, XS_PATH_MAX, "%s/%s.rfxs", HTTPD_ROOT, CNT_LOCK);
	if ((fdout = open(lockfile, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
		err(1, "Could not open(%s)", lockfile);

	if (1 == xscount_version)
	{
		/* Convert version 1 -> version 2 data:
		 * - add timestamp field
		 */
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
			if (write(fdout, &counter, CNT_SZ) != CNT_SZ)
				err(1, "write()");
		}
	}
	else if (2 == xscount_version)
	{
		char		*c;
		int			cmp;
		/* Cleanup version 2 data:
		 * - aggregate duplicate entries
		 * - remove badly sorted entries
		 */
		num = 0;
		if (read(fdin, &counter, CNT_SZ) == CNT_SZ)
			if (write(fdout, &counter, CNT_SZ) != CNT_SZ)
				err(1, "write()");
		if (read(fdin, &counter_prev, CNT_SZ) != CNT_SZ)
			err(1, "read()");
		while (read(fdin, &counter, CNT_SZ) == CNT_SZ)
		{
			if ((c = memchr(counter.filename, '?', sizeof(counter.filename))))
				*c = '\0';
			if (!counter.filename[0])
				continue;
			cmp = strncmp(counter_prev.filename, counter.filename, sizeof(counter.filename));
			if (cmp < 0)
			{
				/* different: write previous entry */
				if (write(fdout, &counter_prev, CNT_SZ) != CNT_SZ)
					err(1, "write()");
			}
			else if (cmp > 0)
			{
				/* previous > current -> ignore current */
				continue;
			}
			else
			{
				/* same name: aggregate data */
				counter.total += counter_prev.total;
				counter.month += counter_prev.month;
				counter.today += counter_prev.today;
			}
			num++;
			memcpy(&counter_prev, &counter, CNT_SZ);
		}
		if (write(fdout, &counter, CNT_SZ) != CNT_SZ)
			err(1, "write()");
	}
	else
		errx(1, "Cannot convert data: corrupt or unknown version");

	close(fdin); close(fdout);

	if (rename(lockfile, counterfile))
	{
		remove(lockfile);
		err(1, "Could not rename counter file");
	}
	printf("Successfully converted %d records\n", num);
	return(0);
}
