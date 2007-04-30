/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: convert.c,v 1.13 2006/12/06 20:56:53 johans Exp $ */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<string.h>
#include	<sys/stat.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"path.h"
#include	"convert.h"

const char *
convertpath(const char *org)
{
	static	char		path[XS_PATH_MAX];
	const	struct	passwd	*userinfo;
	char			person[XS_USER_MAX];
	char			*slash, *userpos;
	int			len;

	if (!strncmp(org, "/~", 2))
	{
		strlcpy(person, org + 2, XS_USER_MAX);
		if ((slash = strchr(person, '/')))
			*slash++ = '\0';
		if (!(userinfo = getpwnam(person)))
			return NULL;
		/* transform_user_dir */
		if ((userpos = strstr(config.users->htmldir, "%u")))
		{
			len = userpos - config.users->htmldir;
			snprintf(path, XS_PATH_MAX, "%*.*s%s%s/",
				len, len, config.users->htmldir,
				userinfo->pw_name,
				userpos + 2);
		}
		else
			snprintf(path, XS_PATH_MAX, "%s/%s/",
				userinfo->pw_dir, config.users->htmldir);
		if (slash)
			strlcat(path, slash, XS_PATH_MAX);
	}
	else if (current == config.users)
		snprintf(path, XS_PATH_MAX, "%s%s",
			calcpath(config.system->htmldir), org);
	else /* use htdocs dir for this vhost */
		snprintf(path, XS_PATH_MAX, "%s%s",
			calcpath(current->htmldir), org);
	return (path);
}
