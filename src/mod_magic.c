/* Copyright (C) 2009 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	<magic.h>

#include	"malloc.h"
#include	"modules.h"
#include	"constants.h"

magic_t		magic_cookie = NULL;
char		*magic_filename = NULL;

bool	mime_magic	(const char *);
bool	mime_magic_config(const char *, const char *);
bool	mime_magic_open	(void);

bool
mime_magic(const char *filename)
{
	const char	*mimetype;

	if (!filename || !filename[0])
		return false;

	if (!(mimetype = magic_file(magic_cookie, filename)))
		return false;

	setenv("CONTENT_TYPE", mimetype, 1);
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
	.head_handler = mime_magic,
	.config_general = mime_magic_config,
};

