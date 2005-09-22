/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: extra.c,v 1.16 2005/09/22 18:11:59 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */
#ifdef		HAVE_TIME_H
#ifdef		TIME_WITH_SYS_TIME
#include	<time.h>
#endif		/* TIME_WITH_SYS_TIME */
#endif		/* HAVE_TIME_H */
#include	<unistd.h>
#include	<signal.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<pwd.h>
#include	<ctype.h>

#include	"extra.h"
#include	"local.h"
#include	"httpd.h"
#include	"mystring.h"

#ifndef		HAVE_STRCASESTR
const	char	*
strcasestr(const char *big, const char *little)
{
	size_t		len;
	char		*search, *newbig, *newlittle;
	const char	*result;

	if (!(newbig = strdup(big)))
		return(NULL);
	if (!(newlittle = strdup(little)))
	{
		free(newbig);
		return(NULL);
	}

	for (search = newlittle; *search; search++)
		if (isupper(*search))
			*search = tolower(*search);
	for (search = newbig; *search; search++)
		if (isupper(*search))
			*search = tolower(*search);
	search = strstr(newbig, newlittle);
	result = search ? big + (search - newbig) : NULL;
	free(newbig); free(newlittle);
	return(result);
}
#endif		/* HAVE_STRCASESTR */

int
mysleep(int seconds)
{
	struct	timeval	timeout;

	timeout.tv_usec = 0;
	timeout.tv_sec = seconds;
	return(select(0, NULL, NULL, NULL, &timeout) == 0);
}

#ifndef		HAVE_KILLPG
int
killpg(pid_t process, int sig)
{
	if (!process)
		process = getpid();
	return(kill(-process, sig));
}
#endif		/* HAVE_KILLPG */

int
match(const char *total, const char *pattern)
{
	int		x, y;

	for (x = 0, y = 0; pattern[y]; x++, y++)
	{
		if ((!total[x]) && (pattern[y] != '*'))
			return(0);
		if (pattern[y] == '*')
		{
			while (pattern[++y] == '*')
				/* NOTHING HERE */;
			if (!pattern[y])
				return(1);
			while (total[x])
			{
				int		ret;

				if ((ret = match(total + (x++), pattern + y)))
					return(ret);
			}
			return(0);
		} else
		{
			if ((pattern[y] != '?') &&
				((isupper(total[x]) ? tolower(total[x]) : total[x])
				 != (isupper(pattern[y]) ? tolower(pattern[y]) : pattern[y])))
				return(0);
		}
	}
	return(!total[x]);
}

int
match_list(char *list, const char *browser)
{
	char		*begin, *end, origin;
	int		matches;

	if (!browser)
		return(0);
	if ((begin = list))
	{
		while (*begin)
		{
			end = begin;
			while (*end && (*end != ' '))
				end++;
			origin = *end; *end = 0;
			matches = match(browser, begin);
			*end = origin;
			if (matches)
				return(1);
			begin = end;
			while (*begin == ' ')
				begin++;
		}
	}
	return(0);
}

#ifndef		HAVE_STRERROR

#if		!HAVE_DECL_SYS_ERRLIST
extern	char		*sys_errlist[];
extern	const	int	sys_nerr;
#endif		/* HAVE_DECL_SYS_ERRLIST */

const	char	*
strerror(int code)
{
	if ((code < 0) || (code > sys_nerr))
		return("Undefined error");
	else
		return(sys_errlist[code]);
}
#endif		/* HAVE_STRERROR */
