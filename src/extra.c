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
#include	<stdarg.h>
#ifdef		HAVE_LIBUTIL_H
#include	<libutil.h>
#else		/* HAVE_LIBUTIL_H */
# ifdef		HAVE_UTIL_H
# include	<util.h>
# endif		/* HAVE_UTIL_H */
#endif		/* HAVE_LIBUTIL_H */

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
				const bool	ret =
					match(total + (x++), pattern + y);

				if (ret)
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
eqstring_to_array(char *string, struct maplist **plist)
{
	size_t		num;
	char		*p, *q;
	const char	*is = NULL , *vs = NULL , *idx = NULL;
	struct maplist	*list = NULL;
	enum { s_findkey, s_findeq, s_findval, s_findnext }	state;

	if (!string)
		return 0;

	if (plist)
	{
		MALLOC(list, struct maplist, 1);
		list->size = 0;
		MALLOC(list->elements, struct mapping, list->size);
		*plist = list;
	}

	num = 0;
	state = s_findkey;
	for (p = string; p == string || p[-1]; p++)
	{
		switch (state)
		{
		case s_findkey:
			if (ISALNUM(*p))
			{
				if (list)
					is = p;
				num++;
				state = s_findeq;
			}
			break;
		case s_findeq:
			if ('=' == *p)
				state = s_findval;
			if (list && !ISALNUM(*p))
			{
				STRNDUP(idx, is, p - is);
				maplist_append(list, append_replace, idx, NULL);
			}
			break;
		case s_findval:
			if ('"' == *p && (q = strchr(++p, '"')))
			{
				if (list)
				{
					maplist_append(list, append_replace,
						idx, "%*.*s",
						(int)(q - p), (int)(q - p), p);
					idx = NULL;
				}
				p = q;
				state = s_findkey;
			}
			else if (ISALNUM(*p))
			{
				if (list)
					vs = p;
				state = s_findnext;
			}
			break;
		case s_findnext:
			if (!ISALNUM(*p))
			{
				state = s_findkey;
				if (list)
				{
					maplist_append(list, append_replace,
						idx, "%*.*s",
						(int)(p - vs), (int)(p - vs),
						vs);
					idx = NULL;
				}
			}
			break;
		}
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
	const size_t	sz =
		internal_xstring_to_arrayp(value, array, xstring_to_array);

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
				q = strchr(p, '\0');
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
	if (!array)
		return;
	for (size_t i = 0; i < num; i++)
		free(array[i]);
	free(array);
}

void
free_string_arrayp(char **array)
{
	if (!array)
		return;
	for (char *p = *array; p; p++)
		free(p);
	free(array);
}

ssize_t
fgetfields(FILE *fd, size_t num_fields, ...)
{
	va_list		ap;
	char		*line, *p, *fld;
	char		**argp;
	size_t		sz, lineno, num;

	if (!(line = fparseln(fd, &sz, &lineno, NULL, FPARSEARG)))
		return -1;

	p = line;
	num = 0;
	va_start(ap, num_fields);
	while ((fld = strsep(&p, " \t\n\r")))
	{
		if (!*fld)
			/* skip empty field */
			continue;
		if (++num > num_fields)
			return num_fields;
		argp = va_arg(ap, char **);
		STRDUP(*argp, fld);
	}
	va_end(ap);
	free(line);
	return num;
}

ssize_t
fgetmfields(FILE *fd, char ***fieldsp)
{
	char		*line, *p, *fld;
	char		**fields;
	size_t		sz, lineno, num;

	if (!(line = fparseln(fd, &sz, &lineno, NULL, FPARSEARG)))
		return -1;

	sz /= 2 + 2;
	MALLOC(fields, char *, sz);
	*fieldsp = fields;
	p = line;
	num = 0;
	while ((fld = strsep(&p, " \t\n\r")))
	{
		if (!*fld)
			continue;
		STRDUP(fields[num], fld);
		num++;
	}
	free(line);
	return num;
}

int
get_temp_fd(void)
{
	int	fd;
	char    prefix[] = TEMPORARYPREFIX;

	if (!(fd = mkstemp(prefix)))
		return -1;

	unlink(prefix);

	return fd;
}

int
maplist_append(struct maplist *list, xs_appendflags_t flags, const char *idx, const char *value, ...)
{
	va_list		ap;

	if (flags & (append_ifempty | append_replace))
	for (size_t sz = 0; sz < list->size; sz++)
	{
		if (!strcasecmp(list->elements[sz].index, idx))
		{
			if (flags & append_ifempty)
			{
				return list->size;
			}
			if (flags & append_replace)
			{
				FREE(list->elements[sz].value);
				if (!value || !*value)
					return list->size;
				va_start(ap, value);
				vasprintf(&list->elements[sz].value, value, ap);
				va_end(ap);
				return list->size;
			}
		}
	}

	if (!list->size)
		MALLOC(list->elements, struct mapping, 1);
	else
		REALLOC(list->elements, struct mapping, list->size + 1);

	if (flags & append_prepend)
	{
		for (size_t sz = list->size; sz > 0; sz--)
			list->elements[sz] = list->elements[sz-1];
		STRDUP(list->elements[0].index, idx);
		if (value && *value)
		{
			va_start(ap, value);
			vasprintf(&list->elements[0].value, value, ap);
			va_end(ap);
		}
		else
			list->elements[0].value = NULL;
		list->size++;
		return list->size;
	}

	/* non-existend or duplicate okay: append at the end */
	STRDUP(list->elements[list->size].index, idx);
	if (value && *value)
	{
		va_start(ap, value);
		vasprintf(&list->elements[list->size].value, value, ap);
		va_end(ap);
	}
	else
		list->elements[list->size].value = NULL;
	list->size++;

	return list->size;
}

void
maplist_free(struct maplist *list)
{
	size_t		sz;

	for (sz = 0; sz < list->size; sz++)
	{
		free(list->elements[sz].index);
		free(list->elements[sz].value);
	}
	free(list->elements);
	list->size = 0;
	list->elements = NULL;
}

