/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

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

extern	int
main DECL2(int, argc, char **, argv)
{
	int			x, y, z, comp, total, fd, mode = MODE_TOTAL,
				option;
	char			counterfile[XS_PATH_MAX], url[BUFSIZ];
	countstr		counter;

	while ((option = getopt(argc, argv, "dmt")) != EOF)
	{
		switch(option)
		{
		case 'd':
			mode = MODE_TODAY;
			break;
		case 'm':
			mode = MODE_MONTH;
			break;
		case 't':
			mode = MODE_TOTAL;
			break;
		default:
			errx(1, "Usage: %s -[d|m|t] URL", argv[0]);
		}
	}

	if (argc != (optind + 1))
		errx(1, "URL missing or too many arguments");

	strcpy(url, argv[optind]);

	sprintf(counterfile, "%s/%s", HTTPD_ROOT, CNT_DATA);
	if ((fd = open(counterfile, O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	if ((total = lseek(fd, 0, SEEK_END)) == -1)
		err(1, "Could not lseek()");

	total /= sizeof(countstr);
	if (total < 2)
		errx(1, "Counter file is corrupt");

	x = 0; z = total-1; y = z/2; comp = 1;

	while ((x < (z-1)) && (comp))
	{
		y = (x + z) / 2;
		if (lseek(fd, y * sizeof(countstr), SEEK_SET) == -1)
			err(1, "lseek()");

		if (read(fd, &counter, sizeof(countstr)) != sizeof(countstr))
			err(1, "read()");

		if ((comp = strcmp(url, counter.filename)) < 0)
			z = y;
		else
			x = y;
	}

	if (comp)
		errx(1, "This URL has no counter");

	switch(mode)
	{
	case MODE_TOTAL:
		printf("%d\n", counter.total);
		break;
	case MODE_TODAY:
		printf("%d\n", counter.today);
		break;
	case MODE_MONTH:
		printf("%d\n", counter.month);
		break;
	}
	fflush(stdout);
	close(fd);
	return(0);
}
