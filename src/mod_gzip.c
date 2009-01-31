/* Copyright (C) 2009 Johan van Selst */

#include	"config.h"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<err.h>
#include	<sys/uio.h>
#include	<unistd.h>
#include	<string.h>

#include	<zlib.h>

#include	"httpd.h"
#include	"modules.h"
#include	"extra.h"

bool	gzip_init(void);
int	gzip_handler(int fdin);
int	gunzip_handler(int fdin);
bool	gzip_config_general(const char *key, const char *value);

bool	usecompress = false;

bool
gzip_init(void)
{
	return true;
}

int
gzip_handler(int fdin)
{
	int		len;
	int		fd;
	gzFile		file;
	static char	buf[RWBUFSIZE];

	if (!usecompress)
		return -1;

	if ((fd = get_temp_fd()) < 0)
		return -1;

	if (!(file = gzdopen(dup(fd), "wb")))
	{
		close(fd);
		return -1;
	}

	while ((len = read(fdin, buf, sizeof(buf))) > 0)
		if (gzwrite(file, buf, len) != len)
			break;

	gzclose(file);
	close(fdin);
	if (lseek(fd, (off_t)0, SEEK_SET) < 0)
		return -1;

	return fd;
}

int
gunzip_handler(int fdin)
{
	int		len;
	int		fd;
	gzFile		file;
	static char	buf[RWBUFSIZE];

	if ((fd = get_temp_fd()) < 0)
		return -1;

	if (!(file = gzdopen(fdin, "rb")))
	{
		close(fd);
		return -1;
	}

	while ((len = gzread(file, buf, sizeof(buf))) > 0)
		if (write(fd, buf, len) < 0)
			break;

	gzclose(file);
	if (lseek(fd, (off_t)0, SEEK_SET) < 0)
		return -1;

	return fd;
}

bool
gzip_config_general(const char *key, const char *value)
{
	if (key && !strcasecmp("UzeGzipCompression", key))
	{
		usecompress = !strcasecmp("true", value);
		return true;
	}
	return false;
}

struct module gzip_module =
{
	.name = "gzip decompression",
	.file_extension = ".gz",
	.file_encoding = "gzip",
	.inflate_handler = gunzip_handler,
	.deflate_handler = gzip_handler,
	.config_general = gzip_config_general,
};

