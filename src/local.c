/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: local.c,v 1.10 2004/09/22 17:17:49 johans Exp $ */


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

#ifndef		NOFORWARDS
static	int	transform_user_dir1	PROTO((char *, const struct passwd *,
						int));
static	int	transform_user_dir2	PROTO((char *, const struct passwd *,
						int));
static	int	transform_user_dir3	PROTO((char *, const struct passwd *,
						int));
#endif		/* NOFORWARDS */

extern	int
transform_user_dir DECL3_C_(char *, base, struct passwd *, userinfo,
			int, errors)
{
#ifdef		BUILD_HTTPD
	char		*userpos;

	userpos = strstr(config.users->htmldir, "%u");

	if (userpos)
	{
		int	len = userpos - config.users->htmldir;
		snprintf(base, XS_PATH_MAX, "%*.*s%s%s",
			len, len, config.users->htmldir,
			userinfo->pw_name,
			userpos + 2);
	}
	else
		strncpy(base, config.users->htmldir, XS_PATH_MAX);

	if (base[0] != '/')
		snprintf(base, XS_PATH_MAX, "%s/%s",
			userinfo->pw_dir,
			base);
#else		/* BUILD_HTTPD */
	sprintf(base, "%s/%s/", userinfo->pw_dir, HTTPD_USERDOC_ROOT);
#endif		/* BUILD_HTTPD */
}

static	int
transform_user_dir1 DECL3_C_(char *, base, struct passwd *, userinfo,
			int, errors)
{
#ifdef		BUILD_HTTPD
	sprintf(base, "%s/%s/", userinfo->pw_dir, config.users->htmldir);
#else		/* BUILD_HTTPD */
	sprintf(base, "%s/%s/", userinfo->pw_dir, HTTPD_USERDOC_ROOT);
#endif		/* BUILD_HTTPD */
	(void)errors;
	return(0);
}

static	int
transform_user_dir2 DECL3_C_(char *, base, struct passwd *, userinfo,
			int, errors)
{
	char		linkbuffer[XS_PATH_MAX];

	sprintf(base, "/www/%s", userinfo->pw_name);
	if (readlink(base, linkbuffer, XS_PATH_MAX) < 0)
	{
		if (errors)
			server_error("403 This user does not have a WWW page",
				"LOCAL_NO_PAGE");
		return(1);
	}
	sprintf(base, "/www/%s/", userinfo->pw_name);
	if (strncmp(linkbuffer, "/lwww", 5))
	{
		if (errors)
			server_error("403 Invalid link in /www",
				"LOCAL_INVALID_LINK");
		return(1);
	}
	return(0);
}

static	int
transform_user_dir3 DECL3_C_(char *, base, struct passwd *, userinfo,
			int, errors)
{
	sprintf(base, "/www/%s/", userinfo->pw_name);
	(void)errors;
	return(0);
}
