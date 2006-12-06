/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: local.c,v 1.18 2006/12/06 20:56:53 johans Exp $ */


#include	"config.h"

#include	<pwd.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>

#include	"httpd.h"
#include	"local.h"
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
	snprintf(base, XS_PATH_MAX, "%s/%s/",
		userinfo->pw_dir, HTTPD_USERDOC_ROOT);
#endif		/* BUILD_HTTPD */
	(void) errors;
	return(0);
}

