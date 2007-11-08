/* Copyright (C) 1994, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: setenv.c,v 1.14 2006/12/06 20:56:55 johans Exp $ */

#include	"config.h"

#include	<stddef.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<string.h>

static	char	*findenv		 (const char *, int *);
static	char	**menviron = NULL;

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
	char		*c;
	const char	*cc;
	int		offset;
	size_t		l_value;

	if (menviron && menviron != environ)
	{
		free(menviron);
		menviron = NULL;
	}
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
		free(menviron[offset]);
	}
	else
	{
		int		cnt;
		char		**p;

		cnt = 0;
		if (menviron)
			for (p = menviron; *p; p++)
				cnt++;
		menviron = (char **)realloc(menviron,
		    (size_t)(sizeof(char *) * (cnt + 2)));
		if (!menviron)
			return(-1);
		menviron[cnt + 1] = NULL;
		offset = cnt;
	}
	for (cc = name; *cc && (*cc != '='); cc++)
		/* NOTHING HERE */;
	if (!(menviron[offset] =
		(char *)malloc((size_t)((int)(cc - name) + l_value + 2))))
		return(-1);
	for (c = menviron[offset]; ((*c = *(name++))) && (*c != '='); c++)
		/* NOTHING HERE */;
	for (*(c++) = '='; (*(c++) = *(value++)); )
		/* NOTHING HERE */;
	environ = menviron;
	return (0);
}

int
unsetenv(const char *name)
{
	char		**p;
	int		offset;

	while (findenv(name, &offset))
	{
		for (p = environ + offset; (*p = p[1]) ; p++)
			/* NOTHING HERE */;
	}
	return (0);
}
