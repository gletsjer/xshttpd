/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<sys/stat.h>

#include	"httpd.h"
#include	"local.h"

extern	const	char	*
convertpath DECL1C(char *, orig)
{
	static	char		buffer[XS_PATH_MAX];
	const	struct	passwd	*userinfo;
	char			person[32];

	if (!strncmp(orig, "/~", 2))
	{
		strncpy(person, orig + 2, 31);
		person[31] = 0;
		strtok(person, "/");
		if (!(userinfo = getpwnam(person)))
			strcpy(buffer, "UNKNOWN_USER");
		else if (transform_user_dir(buffer, userinfo, 0))
			strcpy(buffer, "PERMISSION_DENIED");
		strncat(buffer, orig + 3 + strlen(person), XS_PATH_MAX - 64);
	} else
		strncpy(buffer, orig, XS_PATH_MAX - 1);
	buffer[XS_PATH_MAX - 1] = 0;
	return(buffer);
}
