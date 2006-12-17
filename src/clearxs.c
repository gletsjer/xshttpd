/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: clearxs.c,v 1.17 2006/12/17 13:29:43 johans Exp $ */

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
#endif		/* HAVE_ERR_H */
#include	<time.h>
#include	<pwd.h>

#include	"xscounter.h"

#define		MODE_TODAY	0
#define		MODE_MONTH	1
#define		MODE_TOTAL	2
#define		MODE_EXPUNGE	4
#define		MODE_NONE	3

int
main(int argc, char **argv)
{
	int		option, fdin, fdout, mode = MODE_NONE;
	countstr	counter;
	char		counterfile[XS_PATH_MAX], lockfile[XS_PATH_MAX],
			clockfile[XS_PATH_MAX];
	struct tm	timeptr;
	time_t		since = 0;

	while ((option = getopt(argc, argv, "dmTx:")) != EOF)
	{
		switch(option)
		{
		case 'd':
			mode = MODE_TODAY;
			break;
		case 'm':
			mode = MODE_MONTH;
			break;
		case 'T':
			mode = MODE_TOTAL;
			break;
		case 'x':
			mode = MODE_EXPUNGE;
			memset(&timeptr, '\0', sizeof timeptr);
			if (!strptime(optarg, "%Y%m%d", &timeptr) ||
					(since = mktime(&timeptr)) < 0)
				errx(1, "Invalid date specification"
					" (try YYYYMMDD)");
			break;
		default:
			errx(1, "Usage: %s -[d|m|T|x yyyymmdd]", argv[0]);
		}
	}

	if (mode == MODE_NONE)
		errx(1, "No mode specified");

	if (argc != optind)
		errx(1, "Too many arguments");

	snprintf(counterfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_DATA);
	if ((fdin  = open(counterfile, O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	snprintf(clockfile, XS_PATH_MAX, "%s/%s", HTTPD_ROOT, CNT_LOCK);
	if ((fdout = open(clockfile, O_WRONLY | O_CREAT | O_TRUNC, 0)) < 0)
		err(1, "Could not open(%s)", clockfile);

	snprintf(lockfile, XS_PATH_MAX, "%s/clearxs.lock", HTTPD_ROOT);
	if ((fdout = open(lockfile, O_WRONLY | O_CREAT | O_TRUNC, 0)) < 0)
		err(1, "Could not open(%s)", lockfile);

	while (read(fdin, &counter, sizeof(countstr)) == sizeof(countstr))
	{
		switch(mode)
		{
		case MODE_TOTAL:
			counter.total = 0;
		case MODE_MONTH:
			counter.month = 0;
		case MODE_TODAY:
			counter.today = 0;
		case MODE_EXPUNGE:
			if (difftime(since, counter.lastseen) < 0)
				continue;
		}
		if (write(fdout, &counter, sizeof(countstr)) !=sizeof(countstr))
			err(1, "write()");
	}
	close(fdin); close(fdout);
	if (rename(lockfile, counterfile))
	{
		remove(lockfile);
		remove(clockfile);
		err(1, "Could not rename counter file");
	}
	remove(lockfile);
	remove(clockfile);
	return(0);
}
