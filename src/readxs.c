/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<signal.h>
#include	<string.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<time.h>
#include	<pwd.h>
#include	<stdbool.h>

#include	"path.h"
#include	"xscounter.h"

#define		MODE_TODAY	0
#define		MODE_MONTH	1
#define		MODE_TOTAL	2
#define		MODE_LAST	3

int
main(int argc, char **argv)
{
	int			x, y, z, comp, total, fd, mode = MODE_TOTAL,
				wrint = 0, option;
	bool			wrset = false;
	char			url[BUFSIZ];
	char			xscount_version;
	const char		*counterfile;
	countstr		counter;

	while ((option = getopt(argc, argv, "dlmtvw:")) != EOF)
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
		case 'l':
			mode = MODE_LAST;
			break;
		case 'v':
			counterfile = calcpath(CNT_DATA);
			if ((fd = open(counterfile, O_RDONLY, 0)) < 0)
				err(1, "Could not open(%s)", counterfile);
			if (read(fd, &xscount_version, 1) != 1)
				err(1, "Could not read(%s)", counterfile);
			printf("%s version id: %u\n", CNT_DATA,
				(unsigned)xscount_version);
			close(fd);
			exit(xscount_version);
		case 'w':
			wrset = true;
			if ((wrint = atoi(optarg)) < 0)
				errx(1, "Cannot set a negative number");
			break;
		default:
			errx(1, "Usage: %s -[d|m|t|l] [-w #] URL", argv[0]);
		}
	}

	if (argc != (optind + 1))
		errx(1, "URL missing or too many arguments");

	strlcpy(url, argv[optind], BUFSIZ);

	counterfile = calcpath(CNT_DATA);
	if ((fd = open(counterfile, wrset ? O_RDWR : O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	if ((total = lseek(fd, (off_t)0, SEEK_END)) == -1)
		err(1, "Could not lseek()");

	total /= sizeof(countstr);
	if (total < 2)
		errx(1, "Counter file is corrupt");

	x = 0; z = total-1; y = z/2; comp = 1;

	while ((x < (z-1)) && (comp))
	{
		y = (x + z) / 2;
		if (lseek(fd, (off_t)(y * sizeof(countstr)), SEEK_SET) == -1)
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
		if (wrset)
			counter.total = wrint;
		printf("%d\n", counter.total);
		break;
	case MODE_TODAY:
		if (wrset)
			counter.today = wrint;
		printf("%d\n", counter.today);
		break;
	case MODE_MONTH:
		if (wrset)
			counter.month = wrint;
		printf("%d\n", counter.month);
		break;
	case MODE_LAST:
		/* XXX: wrset not implemented yet */
		printf("%s", ctime(&counter.lastseen));
		if (wrset)
			errx(1, "lastseen timestamp can not be set");
		break;
	}
	if (wrset)
	{
		if (lseek(fd, (off_t)(y * sizeof(countstr)), SEEK_SET) == -1)
			err(1, "lseek()");
		if (write(fd, &counter, sizeof(countstr)) != sizeof(countstr))
			err(1, "write()");
	}
	fflush(stdout);
	close(fd);
	return(0);
}
