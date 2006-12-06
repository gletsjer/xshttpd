/* Copyright (C) 1994, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: setenv.c,v 1.14 2006/12/06 20:56:55 johans Exp $ */

#include	"config.h"

#include	<stddef.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<unistd.h>

#include	"setenv.h"

static	char	*findenv		 (const char *, int *);

char	*
getenv(const char *name)
{
	int		offset;

	return (findenv(name, &offset));
}

static	char	*
findenv(const char *name, int *offset)
{
	int		len;
	const	char	*np;
	char		**p, *c;

	if (!name || !environ)
		return(NULL);
	for (np = name; *np && (*np != '='); ++np)
		continue;
	len = np - name;
	for (p = environ; ((c = *p)); ++p)
	{
		if (!strncmp(c, name, len) && (c[len] == '='))
		{
			*offset = p - environ;
			return(c + len + 1);
		}
	}
	return (NULL);
}

int
setenv(const char *name, const char *value, int rewrite)
{
	static	int	alloced = 0;
	char		*c;
	int		l_value, offset;

	if (*value == '=')
		value++;
	l_value = strlen(value);
	if ((c = findenv(name, &offset)))
	{
		if (!rewrite)
			return(0);
		if (strlen(c) >= l_value)
		{
			while ((*(c++) = *(value++)))
				/* NOTHING HERE */;
			return(0);
		}
	}
	else
	{
		int		cnt;
		char		**p;

		for (p = environ, cnt = 0; *p; p++, cnt++)
			/* NOTHING HERE */;
		if (alloced)
		{
			environ = (char **)realloc((char *)environ,
			    (size_t)(sizeof(char *) * (cnt + 2)));
			if (!environ)
				return(-1);
		}
		else
		{
			alloced = 1;
			p = (char **)malloc((size_t)(sizeof(char *) * (cnt+2)));
			if (!p)
				return(-1);
			bcopy((char *)p, (char *)environ, cnt * sizeof(char *));
			environ = p;
		}
		environ[cnt + 1] = NULL;
		offset = cnt;
	}
	for (c = (char *)name; *c && (*c != '='); c++)
		/* NOTHING HERE */;
	if (!(environ[offset] =
		(char *)malloc((size_t)((int)(c - name) + l_value + 2))))
		return(-1);
	for (c = environ[offset]; ((*c = *(name++))) && (*c != '='); c++)
		/* NOTHING HERE */;
	for (*(c++) = '='; (*(c++) = *(value++)); )
		/* NOTHING HERE */;
	return (0);
}

void
unsetenv(const char *name)
{
	char		**p;
	int		offset;

	while (findenv(name, &offset))
	{
		for (p = environ + offset; (*p = p[1]) ; p++)
			/* NOTHING HERE */;
	}
}
