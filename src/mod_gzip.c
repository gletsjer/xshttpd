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
#include	"malloc.h"
#include	"modules.h"
#include	"extra.h"

bool	gzip_init(void);
int	gzip_handler(int fdin);
bool	gzip_config_general(const char *key, const char *value);

void *	gzip_open	(int fd);
int	gzip_read	(void *fdp, char *buf, size_t len);
int	gzip_close	(void *fdp);

void *	gunzip_open	(int fd);
int	gunzip_read	(void *fdp, char *buf, size_t len);
int	gunzip_close	(void *fdp);

struct encoding_filter	gzip_filter =
	{ gzip_open, gzip_read, gzip_close };

struct encoding_filter	gunzip_filter =
	{ gunzip_open, gunzip_read, gunzip_close };

bool	usecompress = false;

bool
gzip_init(void)
{
	return true;
}

void *
gzip_open(int fd)
{
	int	*fdp;

	if (!usecompress)
		return NULL;

	MALLOC(fdp, int, 1);
	*fdp = fd;

	return fdp;
}

int
gzip_read(void *fdp, char *buf, size_t len)
{
	int		rlen;
	char		rbuf[RWBUFSIZE*90/100];
	unsigned long	clen;

	rlen = read(*(int *)fdp, rbuf, sizeof(rbuf));
	if (rlen <= 0)
		return rlen;

	clen = len;
	compress((unsigned char *)buf, &clen, (unsigned char *)rbuf, rlen);
	return (int)clen;
}

int
gzip_close(void *fdp)
{
	if (!usecompress)
		return -1;

	return close(*(int *)fdp);
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

void *
gunzip_open(int fdin)
{
	return (void *)gzdopen(fdin, "rb");
}

int
gunzip_read(void *fdp, char *buf, size_t len)
{
	return gzread((gzFile)fdp, buf, len);
}

int
gunzip_close(void *fdp)
{
	return gzclose((gzFile)fdp);
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
//	.deflate_filter = &gzip_filter,
	.inflate_filter = &gunzip_filter,
	.config_general = gzip_config_general,
};

