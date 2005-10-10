/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: convert.c,v 1.9 2005/10/10 18:40:16 johans Exp $ */

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
	static	char		buffer[XS_PATH_MAX];
	const	struct	passwd	*userinfo;
	char			person[32];

	if (!strncmp(org, "/~", 2))
	{
		strlcpy(person, org + 2, 32);
		person[31] = 0;
		strtok(person, "/");
		if (!(userinfo = getpwnam(person)))
			strcpy(buffer, "UNKNOWN_USER");
		else if (transform_user_dir(buffer, userinfo, 0))
			strcpy(buffer, "PERMISSION_DENIED");
		strlcat(buffer, org + 3 + strlen(person), XS_PATH_MAX);
	} else if (org[0] == '/')
		strlcpy(buffer, org, XS_PATH_MAX);
	else
		snprintf(buffer, XS_PATH_MAX, "%s%s", currentdir, org);
	buffer[XS_PATH_MAX - 1] = 0;
	return(buffer);
}
