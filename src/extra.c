/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<time.h>
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
#include	"malloc.h"

static size_t	internal_xstring_to_arrayp(const char *, char ***, size_t (*)(const char *, char **)) WARNUNUSED;
static size_t	internal_xstring_to_arraypn(const char *, char ***, size_t (*)(const char *, char **)) WARNUNUSED;
static int		qcmp(const char **, const char **);

bool
mysleep(int sec)
{
	return !select(0, NULL, NULL, NULL, &(struct timeval){.tv_sec = sec});
}

struct tm *
localtimenow(void)
{
	time_t	now;

	time(&now);
	return localtime(&now);
}

char *
gmtimestamp(void)
{
	static	char	buffer[90];
	time_t	now;

	time(&now);
	strftime(buffer, sizeof(buffer),
		"%d/%b/%Y:%H:%M:%S +0000", gmtime(&now));
	return (char *)buffer;
}

bool
match(const char *total, const char *pattern)
{
	int		x, y;

	for (x = 0, y = 0; pattern[y]; x++, y++)
	{
		if ((!total[x]) && (pattern[y] != '*'))
			return false;
		if (pattern[y] == '*')
		{
			while (pattern[++y] == '*')
				/* NOTHING HERE */;
			if (!pattern[y])
				return true;
			while (total[x])
			{
				bool		ret;

				if ((ret = match(total + (x++), pattern + y)))
					return ret;
			}
			return false;
		} else
		{
			if ((pattern[y] != '?') &&
				((isupper(total[x]) ? tolower(total[x]) : total[x])
				 != (isupper(pattern[y]) ? tolower(pattern[y]) : pattern[y])))
				return false;
		}
	}
	return (!total[x]);
}

bool
match_list(char *list, const char *browser)
{
	char		*begin, *end, origin;
	bool		matches;

	if (!browser)
		return false;
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
				return true;
			begin = end;
			while (*begin == ' ')
				begin++;
		}
	}
	return false;
}

/* Convert whitespace/comma-separated index=value string into mapping */
#define ISALNUM(p) (((p) >= '0' && (p) <= '9') || ((p) >= 'a' && (p) <= 'z') ||\
		((p) >= 'A' && (p) <= 'Z') || (p) == '-' || (p) == '_')
size_t
eqstring_to_array(char *string, struct mapping *map)
{
	size_t		num;
	char		*p, *q;
	enum { s_findkey, s_findeq, s_findval, s_findnext }	state;

	if (!string)
		return 0;
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
				num++;
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
					map[num-1].value = p + 1;
					p = q;
				}
				state = s_findnext;
			}
			else if (ISALNUM(*p))
			{
				if (map)
					map[num-1].value = p;
				state = s_findnext;
			}
			break;
		case s_findnext:
			if (!ISALNUM(*p))
			{
				state = s_findkey;
			}
			break;
		}
		if (!ISALNUM(*p) && map)
			*p = '\0';
	}
	return num;
}

/* like string_to_array, but malloc's data */
static size_t
internal_xstring_to_arrayp(const char *value, char ***array, size_t (*xstring_to_array)(const char *, char **))
{
	size_t	sz;

	sz = xstring_to_array(value, NULL);
	REALLOC(*array, char *, sz);
	sz = xstring_to_array(value, *array);
	return sz;
}

static size_t
internal_xstring_to_arraypn(const char *value, char ***array, size_t (*xstring_to_array)(const char *, char **))
{
	size_t	sz;

	sz = internal_xstring_to_arrayp(value, array, xstring_to_array);
	if (!sz)
		return sz;

	REALLOC(*array, char *, sz + 1);
	(*array)[sz] = NULL;
	return sz;
}

size_t
string_to_arrayp(const char *value, char ***array)
{
	return internal_xstring_to_arrayp(value, array, &string_to_array);
}

size_t
qstring_to_arrayp(const char *value, char ***array)
{
	return internal_xstring_to_arrayp(value, array, &qstring_to_array);
}

size_t
string_to_arraypn(const char *value, char ***array)
{
	return internal_xstring_to_arraypn(value, array, &string_to_array);
}

size_t
qstring_to_arraypn(const char *value, char ***array)
{
	return internal_xstring_to_arraypn(value, array, &qstring_to_array);
}

/* Convert whitespace/comma-separated string into array (config) */
size_t
string_to_array(const char *value, char **array)
{
	size_t	num, len;
	char	*valuecopy;
	char	*prev = NULL, *next;

	if (!value)
		return 0;

	STRDUP(valuecopy, value);
	next = valuecopy;

	num = 0;
	len = strlen(valuecopy);

	while ((prev = strsep(&next, ", \t")))
		if (*prev)
		{
			if (array)
				STRDUP(array[num], prev);
			num++;
		}

	free(valuecopy);
	return num;
}

static int
qcmp(const char **a, const char **b)
{
	char		*p;
	double		qvala, qvalb;

	qvala = qvalb = 1;
	if ((p = strstr(*a, "q=")))
		qvala = atof(p + 2);
	if ((p = strstr(*b, "q=")))
		qvalb = atof(p + 2);

	if (qvala > 1)
		qvala = 1;
	else if (qvala < 0)
		qvala = 0;
	if (qvalb > 1)
		qvalb = 1;
	else if (qvalb < 0)
		qvalb = 0;

	return qvala < qvalb ? 1 : qvala > qvalb ? -1 : 0;
}

/* Convert comma separated http header into array */
size_t
qstring_to_array(const char *value, char **array)
{
	size_t		num = 0;
	bool		has_qvalues = false;
	char		*valuecopy;
	char		*prev = NULL, *next;

	if (!value)
		return 0;

	STRDUP(valuecopy, value);
	next = valuecopy;

	while ((prev = strsep(&next, ",")))
		if (*prev)
		{
			char	*p, *q;
			char	*term = NULL;

			if (array)
			{
				/* strip whitespace */
				for (p = prev; isspace(*p); p++)
					/* DO NOTHING */;
				if (!*p)
					continue;
				STRDUP(term, p);
				p = term;
				q = p + strlen(p);
				while (isspace(*q--))
					*q = '\0';
				while (p++ < q)
					if (isspace(*p))
					{
						memmove(p, p + 1, q - p + 1);
						q--;
						p--;
					}
			}
			num++;

			/* q=0 means term should be ignored */
			if ((p = strstr(prev, "q=")))
				has_qvalues = true;
			if (p && !strncmp(p, "q=0.000", strlen(p)))
			{
				num--;
				if (array)
					free(term);
				term = NULL;
			}

			if (term)
				array[num - 1] = term;
		}

	/* optional: fake qvalues */
	if (array && !has_qvalues)
		for (size_t i = 0; i < num; i++)
			if (strstr(array[i], "/*"))
			{
				REALLOC(array[i], char, strlen(array[i]) + 8);
				if (!strcmp(array[i], "*/*"))
					strcat(array[i], ";q=0.01");
				else
					strcat(array[i], ";q=0.02");
			}

	if (array)
		qsort(array, num, sizeof(char *),
			(int (*)(const void *, const void *))qcmp);

	free(valuecopy);
	return num;
}

void
free_string_array(char **array, size_t num)
{
	size_t	i;

	if (!array)
		return;
	for (i = 0; i < num; i++)
		free(array[i]);
	free(array);
}

void
free_string_arrayp(char **array)
{
	char	*p;

	if (!array)
		return;
	for (p = *array; p; p++)
		free(p);
	free(array);
}
