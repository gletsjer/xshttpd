/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: path.c,v 1.8 2005/07/06 11:27:30 johans Exp $ */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"local.h"
#include	"path.h"
#include	"mystring.h"

const	char	*
calcpath(const char *filename)
{
	static	char	buffer[XS_PATH_MAX];
	size_t		len;

	if (*filename == '/')
		strlcpy(buffer, filename, XS_PATH_MAX);
	else
	{
		if (config.systemroot)
			strlcpy(buffer, config.systemroot, XS_PATH_MAX);
		else
			strlcpy(buffer, HTTPD_ROOT, XS_PATH_MAX);
		buffer[XS_PATH_MAX - 2] = 0;
		len = strlen(buffer);
		buffer[len++] = '/';
		strlcat(buffer, filename, XS_PATH_MAX);
	}
	return(buffer);
}
