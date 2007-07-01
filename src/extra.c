/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: extra.c,v 1.19 2006/12/06 20:56:53 johans Exp $ */

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
#include	<string.h>
#include	<ctype.h>

#include	"htconfig.h"
#include	"extra.h"
#include	"httpd.h"

int
mysleep(int seconds)
{
	struct	timeval	timeout;

	timeout.tv_usec = 0;
	timeout.tv_sec = seconds;
	return(select(0, NULL, NULL, NULL, &timeout) == 0);
}

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

/* Convert whitespace/comma-seperated index=value string into mapping */
#define ISALNUM(p) ((p >= '0' && p <= '9') || (p >= 'a' && p <= 'z') || \
		(p >= 'A' && p <= 'Z') || p == '-' || p == '_')
size_t
eqstring_to_array(char *string, struct mapping *map)
{
	size_t		num;
	char		*p, *q;
	enum { s_findkey, s_findeq, s_findval, s_findnext }	state;

	num = 0;
	state = s_findkey;
	for (p = string; *p; p++)
	{
		switch (state)
		{
		case s_findkey:
			if (ISALNUM(*p))
			{
				if (map)
				{
					map[num].index = p;
					map[num].value = NULL;
				}
				state = s_findeq;
			}
			break;
		case s_findeq:
			if ('=' == *p)
			{
				state = s_findval;
			}
			break;
		case s_findval:
			if ('"' == *p && (q = strchr(p + 1, '"')))
			{
				if (map)
				{
					*p = *q = '\0';
					map[num].value = p + 1;
					p = q;
				}
				state = s_findnext;
			}
			else if (ISALNUM(*p))
			{
				if (map)
					map[num].value = p;
				state = s_findnext;
			}
			break;
		case s_findnext:
			if (!ISALNUM(*p))
			{
				state = s_findkey;
				num++;
			}
			break;
		}
		if (!ISALNUM(*p) && map)
			*p = '\0';
	}
	num++;
	if (map)
	{
		map[num].index = NULL;
		map[num].value = NULL;
	}
	return num;
}

/* like string_to_array, but malloc's data */
size_t
string_to_arrayp(char * value, char ***array)
{
	size_t	sz;
	char	**p;

	/* free old data if !NULL */
	if (*array)
		for (p = *array; *p; p++)
			free(*p);

	p = *array;
	sz = string_to_array(value, NULL);
	realloc(p, sz);
	sz = string_to_array(value, p);
	return sz;
}

/* Convert whitespace/comma-seperated string into array */
size_t
string_to_array(char *value, char **array)
{
	size_t	num;
	char	*prev = NULL, *next = value;

	while ((prev = strsep(&next, ", \t")))
		if (*prev)
		{
			if (array)
				array[num] = strdup(prev);
			num++;
		}

	num++;
	if (array)
		array[num] = NULL;
	return num;
}

uid_t
valid_user(const char *user)
{
	struct	passwd	*userinfo;
	char		*shell;

	/* user must exit */
	if (!user || !(userinfo = getpwnam(user)))
		return 0;
	/* ... not be root */
	if (!userinfo->pw_uid || !userinfo->pw_shell)
		return 0;
	/* ... and have a valid login shell */
	setusershell();
	while ((shell = getusershell()))
		if (!strcmp(shell, userinfo->pw_shell))
			return userinfo->pw_uid;
	endusershell();

	return 0;
}

