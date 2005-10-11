/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: convert.c,v 1.10 2005/10/11 20:25:04 johans Exp $ */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<string.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"local.h"
#include	"mystring.h"
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
		else if (transform_user_dir(path, userinfo, 0))
			strlcpy(path, "PERMISSION_DENIED", XS_PATH_MAX);
		strlcat(path, org + 3 + strlen(person), XS_PATH_MAX);
	} else if (org[0] == '/')
		strlcpy(path, org, XS_PATH_MAX);
	else
		snprintf(path, XS_PATH_MAX, "%s%s", currentdir, org);
	path[XS_PATH_MAX - 1] = 0;
	return (path);
}
