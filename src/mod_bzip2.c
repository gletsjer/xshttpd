/* Copyright (C) 2009-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<err.h>
#include	<sys/uio.h>
#include	<unistd.h>
#include	<string.h>

#include	<bzlib.h>

#include	"modules.h"

void	*bzip2_open	(int fd);
int	bzip2_read	(void *fdp, char *buf, size_t len);
int	bzip2_close	(void *fdp);
off_t	bzip2_seek	(void *fdp, off_t offset, int whence);

struct encoding_filter	bzip2_filter =
	{ bzip2_open, bzip2_read, bzip2_close, bzip2_seek, NULL };

void *
bzip2_open(int fd)
{
	return (void *)BZ2_bzdopen(fd, "rb");
}

int
bzip2_read(void *fdp, char *buf, size_t len)
{
	return BZ2_bzread((BZFILE *)fdp, buf, len);
}

int
bzip2_close(void *fdp)
{
	BZ2_bzclose((BZFILE *)fdp);
	return 0;
}

off_t
bzip2_seek(void *fdp, off_t offset, int whence)
{
	char	buf[RWBUFSIZE];
	size_t	len;
	off_t	totalread = 0;
	int	ret;

	/* whence flag is ignored */
	(void)whence;

	while (totalread < offset)
	{
		if (totalread + RWBUFSIZE < offset)
			len = offset - totalread;
		else
			len = RWBUFSIZE;
		ret = BZ2_bzread((BZFILE *)fdp, buf, len);
		if (ret < 0)
			return ret;
		totalread += ret;
	}

	return totalread;
}

struct module bzip2_module =
{
	.name = "bzip2 decompression",
	.file_extension = ".bz2",
	.file_encoding = "bzip2",
	.inflate_filter = &bzip2_filter,
};

