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

static const char *
convertpathandroot(const char *org, size_t *rootlen)
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
			*rootlen = strlen(BITBUCKETNAME);
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
		else if (config.users->htmldir[0] == '~' &&
				config.users->htmldir[1] == '/')
			snprintf(path, XS_PATH_MAX, "%s/%s/",
				userinfo->pw_dir, config.users->htmldir + 2);
		else if (config.users->htmldir[0] != '/')
			snprintf(path, XS_PATH_MAX, "%s/%s/",
				userinfo->pw_dir, config.users->htmldir);
		else
			/* Path starts with leading slash */
			strlcpy(path, config.users->htmldir, XS_PATH_MAX);
		*rootlen = strlen(path) - 1;
		if (slash)
			strlcat(path, slash, XS_PATH_MAX);
	}
	else if (*org != '/')
	{
		char	*pwd = getenv("PWD");

		*rootlen = strlen(pwd);
		snprintf(path, XS_PATH_MAX, "%s/%s", pwd, org);
	}
	else if (current == config.users)
	{
		*rootlen = strlen(config.system->htmldir);
		snprintf(path, XS_PATH_MAX, "%s%s", config.system->htmldir, org);
	}
	else /* use htdocs dir for this vhost */
	{
		*rootlen = strlen(current->htmldir);
		snprintf(path, XS_PATH_MAX, "%s%s", current->htmldir, org);
	}
	while (*rootlen > 0 && path[*rootlen - 1] == '/')
		*rootlen--;
	return (path);
}

const char *
convertpath(const char *org)
{
	size_t	rootlen;

	return convertpathandroot(org, &rootlen);
}

char *
getdocroot(const char *org)
{
	char	*path;
	size_t	rootlen;

	path = (char *)convertpathandroot(org, &rootlen);
	if (rootlen > 0)
		path[rootlen] = '\0';

	return path;
}


