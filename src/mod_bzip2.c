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

bool	bzip2_handler(const char *filename, int fdin, int fdout);

/* NOTE: This is an exact copy of mod_bzip2 */
bool
bzip2_handler(const char *filename, int fdin, int fdout)
{
	int		len;
	BZFILE		*file;
	static char	buf[BUFSIZ];

	if (!(file = BZ2_bzdopen(fdin, "rb")))
		return false;

	while ((len = BZ2_bzread(file, buf, sizeof(buf))) > 0)
		if (write(fdout, buf, len) < 0)
			break;

	BZ2_bzclose(file);
	(void)filename;
	return 0 == len;
}

struct module bzip2_module =
{
	.name = "bzip2 decompression",
	.file_extension = ".bz2",
	.file_encoding = "bzip2",
	.inflate_handler = bzip2_handler,
};

