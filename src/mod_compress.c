/* Copyright (C) 2009 Johan van Selst */

#include	"config.h"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<err.h>
#include	<sys/uio.h>
#include	<unistd.h>
#include	<string.h>

#include	<zlib.h>

#include	"modules.h"

bool	compress_handler(const char *filename, int fdin, int fdout);

/* NOTE: This is an exact copy of mod_compress */
bool
compress_handler(const char *filename, int fdin, int fdout)
{
	int		len;
	gzFile		file;
	static char	buf[BUFSIZ];

	if (!(file = gzdopen(fdin, "rb")))
		return false;

	while ((len = gzread(file, buf, sizeof(buf))) > 0)
		if (write(fdout, buf, len) < 0)
			break;

	gzclose(file);
	(void)filename;
	return 0 == len;
}

struct module compress_module =
{
	.name = "compress decompression",
	.file_extension = ".Z",
	.file_encoding = "compress",
	.inflate_handler = compress_handler,
};

