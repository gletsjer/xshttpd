/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: path.c,v 1.10 2005/08/19 18:27:15 johans Exp $ */

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

	if (*filename == '/')
		strlcpy(buffer, filename, XS_PATH_MAX);
	else
		snprintf(buffer, XS_PATH_MAX, "%s/%s",
			config.systemroot ? config.systemroot : HTTPD_ROOT,
			filename);
	return (buffer);
}
