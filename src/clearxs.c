/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: clearxs.c,v 1.5 2004/11/26 16:45:09 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<signal.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */
#include	<pwd.h>

#include	"xscounter.h"
#include	"mygetopt.h"

#define		MODE_TODAY	0
#define		MODE_MONTH	1
#define		MODE_TOTAL	2
#define		MODE_NONE	3

extern	int
main(int argc, char **argv)
{
	int		option, x, fd, mode = MODE_NONE;
	countstr	counter;
	char		counterfile[XS_PATH_MAX];

	while ((option = getopt(argc, argv, "dmT")) != EOF)
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
		default:
			errx(1, "Usage: %s -[d|m|T]", argv[0]);
		}
	}

	if (mode == MODE_NONE)
		errx(1, "No mode specified");

	if (argc != optind)
		errx(1, "Too many arguments");

	sprintf(counterfile, "%s/%s", HTTPD_ROOT, CNT_DATA);
	if ((fd = open(counterfile, O_RDWR, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	x = 0;
	while (read(fd, &counter, sizeof(countstr)) == sizeof(countstr))
	{
		switch(mode)
		{
		case MODE_TOTAL:
			counter.total = 0;
		case MODE_MONTH:
			counter.month = 0;
		case MODE_TODAY:
			counter.today = 0;
		}
		if (lseek(fd, x * sizeof(countstr), SEEK_SET) == -1)
			err(1, "lseek()");
		if (write(fd, &counter, sizeof(countstr)) != sizeof(countstr))
			err(1, "write()");
		x++;
	}
	close(fd);
	return(0);
}
