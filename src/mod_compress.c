/* Copyright (C) 2009-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<err.h>
#include	<sys/uio.h>
#include	<unistd.h>
#include	<string.h>

#include	<zlib.h>

#include	"modules.h"
#include	"extra.h"

/* These functions are an exact copy of mod_gzip */
void *	compress_open	(int fd);
int	compress_read	(void *fdp, char *buf, size_t len);
int	compress_close	(void *fdp);
off_t	compress_seek	(void *fdp, off_t offset, int whence);

struct encoding_filter	compress_filter =
	{ compress_open, compress_read, compress_close, compress_seek, NULL };

void *
compress_open(int fdin)
{
	return (void *)gzdopen(fdin, "rb");
}

int
compress_read(void *fdp, char *buf, size_t len)
{
	return gzread((gzFile)fdp, buf, len);
}

int
compress_close(void *fdp)
{
	return gzclose((gzFile)fdp);
}

off_t
compress_seek(void *fdp, off_t offset, int whence)
{
	return gzseek((gzFile)fdp, offset, whence);
}

struct module compress_module =
{
	.name = "compress decompression",
	.file_extension = ".Z",
	.file_encoding = "compress",
	.inflate_filter = &compress_filter,
};

