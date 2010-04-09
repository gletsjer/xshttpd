/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<pwd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/stat.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"malloc.h"
#include	"path.h"
#include	"convert.h"

const char *
convertpath(const char *org)
{
	static	char		path[XS_PATH_MAX];

	if (!strncmp(org, "/~", 2))
	{
		char			*person, *slash;
		const	struct	passwd	*userinfo;
		const	char		*userpos;

		STRDUP(person, org + 2);
		if ((slash = strchr(person, '/')))
			*slash++ = '\0';
		if ((slash = strchr(org + 2, '/')))
			slash++;
		if (!(userinfo = getpwnam(person)))
		{
			free(person);
			return BITBUCKETNAME;
		}
		free(person);
		/* transform_user_dir */
		if ((userpos = strstr(config.users->htmldir, "%u")))
		{
			const int	len = userpos - config.users->htmldir;

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
	else if (*org != '/')
		snprintf(path, XS_PATH_MAX, "%s/%s", getenv("PWD"), org);
	else if (current == config.users)
		snprintf(path, XS_PATH_MAX, "%s%s",
			calcpath(config.system->htmldir), org);
	else /* use htdocs dir for this vhost */
		snprintf(path, XS_PATH_MAX, "%s%s",
			calcpath(current->htmldir), org);
	return (path);
}
