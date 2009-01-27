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

bool	gzip_init(void);
bool	gzip_handler(const char *filename, int fdin, int fdout);
bool	gzip_config_general(const char *key, const char *value);

bool
gzip_init(void)
{
	return true;
}

bool
gzip_handler(const char *filename, int fdin, int fdout)
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

bool
gzip_config_general(const char *key, const char *value)
{
	(void)key;
	(void)value;
	return false;
}

struct module gzip_module =
{
	.name = "gzip interpreter",
	.file_extension = ".gz",
	.file_encoding = "gzip",
	.inflate_handler = gzip_handler,
	.config_general = gzip_config_general,
};

