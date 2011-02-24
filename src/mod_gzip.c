/* Copyright (C) 2009-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<err.h>
#include	<sys/uio.h>
#include	<unistd.h>
#include	<string.h>

#include	<zlib.h>

#include	"extra.h"
#include	"malloc.h"
#include	"modules.h"

/* Functions */
bool	gzip_init(void);
bool	gzip_config_general(const char *key, const char *value);

void *	gzip_open	(int fd);
int	gzip_read	(void *fdp, char *buf, size_t len);
int	gzip_close	(void *fdp);

void *	gunzip_open	(int fd);
int	gunzip_read	(void *fdp, char *buf, size_t len);
int	gunzip_close	(void *fdp);
off_t	gunzip_seek	(void *fdp, off_t offset, int whence);
off_t	gunzip_size	(int fd);

/* Variables */
struct encoding_filter	gzip_filter =
	{ gzip_open, gzip_read, gzip_close, NULL, NULL };

struct encoding_filter	gunzip_filter =
	{ gunzip_open, gunzip_read, gunzip_close, gunzip_seek, gunzip_size };

struct gzstruct
{
	int	fdin;
	int	fdout;
	gzFile	gzf;
	off_t	w_off;
	off_t	r_off;
};

struct module gzip_module =
{
	.name = "gzip decompression",
	.file_extension = ".gz",
	.file_encoding = "gzip",
	.deflate_filter = &gzip_filter,
	.inflate_filter = &gunzip_filter,
	.config_general = gzip_config_general,
};

bool	usecompress = false;

bool
gzip_init(void)
{
	return true;
}

void *
gzip_open(int fd)
{
	gzFile		file;
	int		tempfd;
	struct gzstruct	*gzfs;

	if (!usecompress)
		return NULL;

	if ((tempfd = get_temp_fd()) < 0)
		return NULL;

	if (!(file = gzdopen(tempfd, "wb")))
		return NULL;

	MALLOC(gzfs, struct gzstruct, 1);
	gzfs->fdin = fd;
	gzfs->fdout = dup(tempfd);
	gzfs->gzf = file;
	gzfs->r_off = 0;
	gzfs->w_off = 0;

	return (void *)gzfs;
}

int
gzip_read(void *fdp, char *buf, size_t len)
{
	int		rlen;
	char		rbuf[RWBUFSIZE];
	struct gzstruct	*gzfs = (struct gzstruct *)fdp;

	rlen = read(gzfs->fdin, rbuf, sizeof(rbuf));
	if (rlen > 0)
	{
		gzwrite(gzfs->gzf, rbuf, rlen);
		gzflush(gzfs->gzf, 0);
		gzfs->w_off = lseek(gzfs->fdout, (off_t)0, SEEK_CUR);
	}
	else if (gzfs->gzf)
	{
		gzclose(gzfs->gzf);
		gzfs->gzf = NULL;
	}

	lseek(gzfs->fdout, gzfs->r_off, SEEK_SET);
	rlen = read(gzfs->fdout, buf, len);
	gzfs->r_off += rlen;
	lseek(gzfs->fdout, gzfs->w_off, SEEK_SET);
	return rlen;
}

int
gzip_close(void *fdp)
{
	struct gzstruct	*gzfs = (struct gzstruct *)fdp;

	close(gzfs->fdin);
	close(gzfs->fdout);
	FREE(gzfs);
	return 0;
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

off_t
gunzip_seek(void *fdp, off_t offset, int whence)
{
	return gzseek((gzFile)fdp, offset, whence);
}

off_t
gunzip_size(int fdin)
{
	unsigned char	buf[4];
	uint32_t	usize;
	int		rv;

	rv = lseek(fdin, (off_t)-4, SEEK_END);
	if (rv >= 0)
		rv = read(fdin, (char *)buf, sizeof(buf));
	if (rv < 0)
		return (off_t)-1;

	lseek(fdin, (off_t)0, SEEK_SET);
	usize = buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
	return (off_t)usize;
}

bool
gzip_config_general(const char *key, const char *value)
{
	if (!key)
	{
		gzip_module.deflate_filter = NULL;
		return true;
	}
	else if (!strcasecmp("UzeGzipCompression", key))
	{
		usecompress = !strcasecmp("true", value);
		gzip_module.deflate_filter = &gzip_filter;
		return true;
	}
	return false;
}

