/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<pwd.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>

#include	"httpd.h"
#include	"local.h"
#include	"mystring.h"

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
	switch(localmode)
	{
	case 1:
		return(transform_user_dir1(base, userinfo, errors));
	case 2:
		return(transform_user_dir2(base, userinfo, errors));
	case 3:
		return(transform_user_dir3(base, userinfo, errors));
	default:
		if (errors)
			error("500 Invalid localmode setting");
		return(1);
	}
}

static	int
transform_user_dir1 DECL3_C_(char *, base, struct passwd *, userinfo,
			int, errors)
{
	sprintf(base, "%s/.html/", userinfo->pw_dir);
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
