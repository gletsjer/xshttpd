/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<pwd.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>

#include	"httpd.h"
#include	"local.h"

#ifndef		NOFORWARDS
static	int	transform_user_dir1	PROTO((char *, const struct passwd *,
						int));
static	int	transform_user_dir2	PROTO((char *, const struct passwd *,
						int));
static	int	transform_user_dir3	PROTO((char *, const struct passwd *,
						int));
#endif		/* NOFORWARDS */

/* really rude hack */
char *verenigingen[] = {
	"vertigo",
	"zes",
	"bci",
	"tamar",
	"th-een",
	"panache",
	"boreas",
	"tunacl",
	"stack",
	"footloos",
	"stevin",
	"totelos",
	"esvb",
	"wens",
	"quatsh",
	"attila",
	"tunina",
	"dustria",
	"dynamos",
	"oktopus",
	"elephant",
	"asterix",
	"eshbf",
	"esmgq",
	"demos",
	"theta",
	"nayade",
	"taveres",
	"pfractie",
	"ewe",
	"samourai",
	"dekate",
	"studs",
	"pphaira",
	"ig",
	"terrain",
	"ichthus",
	"tmmarket",
	"certam97",
	"isis",
	"mensa",
	"esc",
	"aegee",
	"weth",
	"squadra",
	"sscessf",
	"digni",
	"disaster",
	"felnoord",
	"audumla",
	"quishoot",
	"meteoor",
	"vgsei",
	"vbi",
	"mosaic",
	"ssre",
	"groep-1",
	"upe",
	"icehawks",
	"ump",
	"upn",
	"pegasus",
	"vanspeyk",
	"suca-een",
	"laa",
	"wvd",
	"ewinkel",
	"svmtprot",
	"estiem",
	"fortes",
	"intermat",
	"stiefel",
	"\0",
	};

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
	return(0);
}

static	int
transform_user_dir2 DECL3_C_(char *, base, struct passwd *, userinfo,
			int, errors)
{
	char		linkbuffer[XS_PATH_MAX];
	int			i = 0;

	sprintf(base, "/www/%s", userinfo->pw_name);
	if (readlink(base, linkbuffer, XS_PATH_MAX) < 0)
	{
		while (verenigingen[i][0] != '\0')
		{
			if (!strcmp(verenigingen[i], userinfo->pw_name))
			{
				if (errors)
				{
					sprintf(linkbuffer, "http://www.stud.tue.nl/%%7E%s/",
						userinfo->pw_name);
					redirect(linkbuffer, 1);
				}
				return(1);
			}
			i++;
		}
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
	return(0);
}
