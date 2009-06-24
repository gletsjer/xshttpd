/* Copyright (C) 2009 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<unistd.h>

#include	<magic.h>

#include	"htconfig.h"
#include	"malloc.h"
#include	"modules.h"
#include	"constants.h"
#include	"extra.h"

magic_t		magic_cookie = NULL;
char		*magic_filename = NULL;

bool	mime_magic	(const char *, int, struct maplist);
bool	mime_magic_config(const char *, const char *);
bool	mime_magic_open	(void);

bool
mime_magic(const char *filename, int fd, struct maplist response_headers)
{
	const char	*mimetype;
	char		input[RWBUFSIZE];
	ssize_t		rd;

	if (!filename || !filename[0])
		return false;

	if (lseek(fd, (off_t)0, SEEK_SET) < 0)
	{
		mimetype = magic_file(magic_cookie, filename);
	}
	else
	{
		if ((rd = read(fd, input, sizeof(input))) < 0)
			return false;
		mimetype = magic_buffer(magic_cookie, input, (size_t)rd);
		lseek(fd, (off_t)0, SEEK_SET);
	}

	maplist_append(response_headers, "Content-type", mimetype);
	return true;
}

bool
mime_magic_config(const char *name, const char *value)
{
	if (!name && !value && magic_filename)
		FREE(magic_filename);
	else if (!strcasecmp(name, "MimeMagicFile"))
		STRDUP(magic_filename, value);
	else
		return false;

	return true;
}

bool
mime_magic_open(void)
{
	if (!(magic_cookie = magic_open(MAGIC_MIME_TYPE | MAGIC_CHECK)))
		return false;

	if (magic_load(magic_cookie, magic_filename) < 0)
	{
		magic_close(magic_cookie);
		return false;
	}

	return true;
}

struct module magic_module =
{
	.name = "magic mime detection",
	.init = mime_magic_open,
#if 0
	.file_headers = mime_magic,
#endif
	.config_general = mime_magic_config,
};

