/* Copyright (C) 2006-2008 by Johan van Selst (johans@stack.nl) */

/* show detailed information from the xs counter datafile */

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
#include	<pwd.h>

#include	"path.h"
#include	"xscounter.h"

typedef	struct	countold
{
	char	filename[128];
	int	total, month, today;
} countold;

int
main(int argc, char *argv[])
{
	int		num, fdin;
	countstr	counter;
	const char	*counterfile;
	char		xscount_version;

	if (argc < 2)
		counterfile = calcpath(CNT_DATA);
	else
		counterfile = argv[1];

	if ((fdin  = open(counterfile, O_RDONLY, 0)) < 0)
		err(1, "Could not open(%s)", counterfile);

	if (read(fdin, &xscount_version, sizeof(char)) != sizeof(char))
		err(1, "Could not read(%s)", counterfile);

	fprintf(stderr, "Reading version %u counter datafile\n", xscount_version);

	if (lseek(fdin, (off_t)0, SEEK_SET) < 0)
		err(1, "lseek()");

	num = 0;
	while (read(fdin, &counter, sizeof(counter)) == sizeof(counter))
	{
		printf("%10lu\t%8u\t%3zu: %s\n",
			(unsigned long)counter.lastseen, counter.total,
			strlen(counter.filename), counter.filename);
	}
	close(fdin);

	return(0);
}
