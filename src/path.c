/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: path.c,v 1.6 2004/11/26 16:45:09 johans Exp $ */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"local.h"
#include	"path.h"
#include	"mystring.h"

extern	const	char	*
calcpath(const char *filename)
{
	static	char	buffer[XS_PATH_MAX];
	size_t		len;

	if (*filename == '/')
		strncpy(buffer, filename, XS_PATH_MAX - 1);
	else
	{
		if (config.systemroot)
			strncpy(buffer, config.systemroot, XS_PATH_MAX - 1);
		else
			strncpy(buffer, HTTPD_ROOT, XS_PATH_MAX - 1);
		buffer[XS_PATH_MAX - 2] = 0;
		len = strlen(buffer);
		buffer[len++] = '/';
		buffer[len] = 0;
		strncat(buffer + len, filename, XS_PATH_MAX - len);
	}
	buffer[XS_PATH_MAX - 1] = 0;
	return(buffer);
}
