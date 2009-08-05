/* Copyright (C) 2009 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<unistd.h>

#include	<magic.h>

#include	"httypes.h"
#include	"malloc.h"
#include	"modules.h"
#include	"constants.h"
#include	"extra.h"

magic_t		magic_cookie = NULL;
char		*magic_filename = NULL;

bool	mime_magic	(const char *, char **);
bool	mime_magic_config(const char *, const char *);
bool	mime_magic_open	(void);

bool
mime_magic(const char *filename, char **headerp)
{
	const char	*mimetype;
	char		input[RWBUFSIZE];
	int		fd;
	ssize_t		rd;
	char		*headers = *headerp;
	char		*type, *nl;

	if (!filename || !filename[0] || !magic_cookie || !magic_filename)
		return false;

	if ((type = strcasestr(headers, "Content-type: ")) &&
			strncasecmp(type + strlen("Content-type: "),
				OCTET_STREAM, strlen(OCTET_STREAM)))
		return true;

	/* Not reached if Content-type is properly defined already;
	 * that is set and not equal to application/octet-stream
	 */

	if (!(mimetype = magic_file(magic_cookie, filename)))
		return false;

	if (!type || strlen(mimetype) > strlen(OCTET_STREAM))
		REALLOC(headers, char, strlen(headers) + strlen(mimetype) + 20);

	if (type)
	{
		type = strcasestr(headers, "Content-type: ");
		nl = strstr(type, "\r\n") + 2;
		memmove(type, nl, strlen(nl) + 1);
	}
	nl = strstr(headers, "\r\n\r\n");
	sprintf(nl + 2, "Content-type: %s\r\n\r\n", mimetype);

	headerp = &headers;
	return true;
}

bool
mime_magic_config(const char *name, const char *value)
{
	if (!name && !value)
	{
		if (magic_filename)
			FREE(magic_filename);
	}
	else if (!strcasecmp(name, "MimeMagicFile"))
		STRDUP(magic_filename, value);
	else
		return false;

	return true;
}

bool
mime_magic_open(void)
{
	if (!magic_filename)
		return false;

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
	.http_headers = mime_magic,
	.config_general = mime_magic_config,
};

