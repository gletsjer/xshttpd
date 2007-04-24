/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: convert.c,v 1.13 2006/12/06 20:56:53 johans Exp $ */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<string.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"local.h"
#include	"convert.h"

const char *
convertpath(const char *org)
{
	static	char		path[XS_PATH_MAX];
	const	struct	passwd	*userinfo;
	char			person[XS_USER_MAX];

	if (!strncmp(org, "/~", 2))
	{
		strlcpy(person, org + 2, XS_USER_MAX);
		person[31] = 0;
		strtok(person, "/");
		if (!(userinfo = getpwnam(person)))
			strlcpy(path, "UNKNOWN_USER", XS_PATH_MAX);
		else if (transform_user_dir(path, userinfo))
			strlcpy(path, "PERMISSION_DENIED", XS_PATH_MAX);
		strlcat(path, org + 3 + strlen(person), XS_PATH_MAX);
	} else if (org[0] == '/')
		strlcpy(path, org, XS_PATH_MAX);
	else
		snprintf(path, XS_PATH_MAX, "%s%s", currentdir, org);
	return (path);
}
