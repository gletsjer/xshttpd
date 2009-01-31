/* Copyright (C) 2009 Johan van Selst */

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

struct encoding_filter	bzip2_filter =
	{ bzip2_open, bzip2_read, bzip2_close };

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

struct module bzip2_module =
{
	.name = "bzip2 decompression",
	.file_extension = ".bz2",
	.file_encoding = "bzip2",
	.inflate_filter = &bzip2_filter,
};

