/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: local.c,v 1.15 2005/01/08 13:25:35 johans Exp $ */


#include	"config.h"

#include	<pwd.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>

#include	"httpd.h"
#include	"local.h"
#include	"mystring.h"
#ifdef		BUILD_HTTPD
# include	"htconfig.h"
#endif		/* BUILD_HTTPD */

int
transform_user_dir(char *base, const struct passwd *userinfo, int errors)
{
#ifdef		BUILD_HTTPD
	char		*userpos;

	userpos = strstr(config.users->htmldir, "%u");

	if (userpos)
	{
		int	len = userpos - config.users->htmldir;
		snprintf(base, XS_PATH_MAX, "%*.*s%s%s/",
			len, len, config.users->htmldir,
			userinfo->pw_name,
			userpos + 2);
	}
	else
		snprintf(base, XS_PATH_MAX, "%s/%s/",
			userinfo->pw_dir, config.users->htmldir);
#else		/* BUILD_HTTPD */
	sprintf(base, "%s/%s/", userinfo->pw_dir, HTTPD_USERDOC_ROOT);
#endif		/* BUILD_HTTPD */
	(void) errors;
	return(0);
}

