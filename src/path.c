/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"local.h"

extern	const	char	*
calcpath DECL1C(char *, name)
{
	static	char	buffer[XS_PATH_MAX];
	size_t		len;

	if (*name == '/')
		strncpy(buffer, name, XS_PATH_MAX - 1);
	else
	{
		strncpy(buffer, rootdir, XS_PATH_MAX - 1);
		buffer[XS_PATH_MAX - 2] = 0;
		len = strlen(buffer);
		buffer[len++] = '/';
		buffer[len] = 0;
		strncat(buffer + len, name, XS_PATH_MAX - len);
	}
	buffer[XS_PATH_MAX - 1] = 0;
	return(buffer);
}
