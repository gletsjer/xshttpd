/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: path.c,v 1.12 2006/12/06 20:56:53 johans Exp $ */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<string.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"local.h"
#include	"path.h"

const	char	*
calcpath(const char *filename)
{
	static	char	buffer[XS_PATH_MAX];
#ifdef		BUILD_HTTPD
	const	char	*dir = config.systemroot;
#else		/* BUILD_HTTPD */
	const	char	*dir = getenv("HTTPD_ROOT");
#endif		/* BUILD_HTTPD */

	if (*filename == '/')
		strlcpy(buffer, filename, XS_PATH_MAX);
	else
		snprintf(buffer, XS_PATH_MAX, "%s/%s",
			dir ? dir : HTTPD_ROOT,
			filename);
	return (buffer);
}
