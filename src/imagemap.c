/*
	imagemap.c - taken from the NCSA httpd distribution, which can
	be found at http://hoohoo.ncsa.uiuc.edu/cgi/

	Previous authors:
	- Kevin Hughes (kevinh@pulua.hcc.hawaii.edu)
	- Eric Haines (erich@eye.com)
	- Rob McCool (robm@ncsa.uiuc.edu)
	- Chris Hyams (cgh@rice.edu)
	- Craig Milo Rogers (rogers@isi.edu)
	- Carlos Varela (cvarela@ncsa.uiuc.edu)

	Changes: cleaned up the code, used the XS-HTTPD defines,
	removed old code which is no longer needed.

	This version by Sven Berkvens (sven@stack.nl).
*/
/* $Id: imagemap.c,v 1.5 2001/05/22 12:19:30 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<sys/types.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<sys/stat.h>

#include	"mystring.h"

#define		MYBUFSIZ	1024
#define		MAXVERTS	1000
#define		X		0
#define		Y		1

#ifndef		NOFORWARDS
static	int	isname			PROTO((int));
static	VOID	servererr		PROTO((const char *));
static	int	pointinpoly		PROTO((void));
static	int	pointincircle		PROTO((void));
static	int	pointinrect		PROTO((void));
static	VOID	sendmesg		PROTO((const char *));
#endif		/* NOFORWARDS */

static	double	testpoint[2], pointarray[MAXVERTS][2];

extern	int
main DECL2(int, argc, char **, argv)
{
	char		input[MYBUFSIZ], *mapname, def[MYBUFSIZ],
			errstr[MYBUFSIZ], *t, mapname2[MYBUFSIZ];
	const	char	*query;
	int		i, j, k, sawpoint = 0;
	FILE		*fp;
	double		dist, mindist = 0;

	if (!(query = getenv("QUERY_STRING")))
		servererr("Invalid usage, client may not support ISMAP");

	if (!(t = strchr(query, ',')))
		servererr("Your client does not support image mapping");
	*t++ = 0;
	i = atoi(query);
	testpoint[X] = (double)i;
	i = atoi(t);
	testpoint[Y] = (double)i;

	if (!(mapname = getenv("PATH_TRANSLATED")))
		servererr("No translated path given by server");
	if (!(fp = fopen(mapname, "r")))
	{
		snprintf(mapname2, MYBUFSIZ, "/vwww/httpd/%s", mapname);
		mapname = mapname2;
		if (!(fp = fopen(mapname, "r")))
		{
			snprintf(errstr, MYBUFSIZ,
				"Could not open map file: `%s'", mapname);
			servererr(errstr);
		}
	}

	while (fgets(input, MYBUFSIZ, fp))
	{
		char		type[MYBUFSIZ], url[MYBUFSIZ], num[10];
		size_t		length;

		length = strlen(input);
		while ((length > 0) && (input[length - 1] <= ' '))
			input[--length] = 0;
		if ((input[0] == '#') || (!input[0]))
			continue;

		type[0] = url[0] = 0;

		for (i = 0; isname(input[i]) && (input[i]); i++)
			type[i] = input[i];
		type[i] = 0;

		while (isspace(input[i]))
			i++;
		for (j = 0; input[i] && isname(input[i]); ++i, ++j)
			url[j] = input[i];
		url[j] = 0;

		if (!strcmp(type, "default") && !sawpoint)
		{
			strcpy(def, url);
			continue;
		}

		k = 0;
		while (input[i])
		{
			while (isspace(input[i]) || (input[i] == ','))
				i++;
			j = 0;
			while (isdigit(input[i]))
				num[j++] = input[i++];
			num[j] = '\0';
			if (num[0])
			{
				j = atoi(num);
				pointarray[k][X] = (double)j;
			} else
				break;
			while (isspace(input[i]) || (input[i] == ','))
				i++;
			j = 0;
			while (isdigit(input[i]))
				num[j++] = input[i++];
			num[j] = 0;
			if (num[0])
			{
				j = atoi(num);
				pointarray[k++][Y] = (double)j;
			} else
				servererr("Missing y value.");
			if (k == (MAXVERTS - 1))
				break;
		}
		pointarray[k][X] = -1;
		if (!strcasecmp(type, "poly"))
		{
			if (pointinpoly())
				sendmesg(url);
		}
		if (!strcasecmp(type, "circle"))
		{
			if (pointincircle())
				sendmesg(url);
		}
		if (!strcasecmp(type, "rect"))
		{
			if (pointinrect())
				sendmesg(url);
		}
		if (!strcasecmp(type, "point"))
		{
			dist = ((testpoint[X] - pointarray[0][X]) *
				(testpoint[X] - pointarray[0][X])) +
				((testpoint[Y] - pointarray[0][Y]) *
				(testpoint[Y] - pointarray[0][Y]));
			if ((!sawpoint) || (dist < mindist))
			{
				mindist = dist;
				strcpy(def,url);
			}
			sawpoint++;
		}
	}
	if (def[0])
		sendmesg(def);
	servererr("No default specified");
	(void)argc;
	(void)argv;
	return(0);
}

static	VOID
sendmesg DECL1C(char *, url)
{
	printf("Location: %s\nContent-type: text/html\n\n", url);
	printf("<HTML><HEAD><TITLE>Moved</TITLE></HEAD><BODY><H1>Moved</H1>\n");
	printf("This document has <A HREF=\"%s\">moved</A>\n", url);
	printf("</BODY></HTML>\n");
	exit(1);
}

static	int
pointinrect DECL0
{
	return ((testpoint[X] >= pointarray[0][X]) &&
		(testpoint[X] <= pointarray[1][X]) &&
		(testpoint[Y] >= pointarray[0][Y]) &&
		(testpoint[Y] <= pointarray[1][Y]));
}

static	int
pointincircle DECL0
{
	int		radius1, radius2;

	radius1 =	((pointarray[0][Y] - pointarray[1][Y]) *
			 (pointarray[0][Y] - pointarray[1][Y])) +
			((pointarray[0][X] - pointarray[1][X]) *
			 (pointarray[0][X] - pointarray[1][X]));
	radius2 =	((pointarray[0][Y] - testpoint[Y]) *
			 (pointarray[0][Y] - testpoint[Y])) +
			((pointarray[0][X] - testpoint[X]) *
			 (pointarray[0][X] - testpoint[X]));
	return (radius2 <= radius1);
}

static	int
pointinpoly DECL0
{
	int		i, numverts, xflag0, crossings;
	double		*p, *stop, tx, ty, y;

	for (i = 0; (pointarray[i][X] != -1) && (i < MAXVERTS); i++)
		/* NOTHING HERE */;
	numverts = i; crossings = 0;
	tx = testpoint[X]; ty = testpoint[Y];
	y = pointarray[numverts - 1][Y];

	p = (double *)pointarray + 1;
	if ((y >= ty) != (*p >= ty))
	{
		if ((xflag0 = (pointarray[numverts - 1][X] >= tx)) ==
			(*(double *)pointarray >= tx))
		{
			if (xflag0)
				crossings++;
		} else
		{
			crossings += ((pointarray[numverts - 1][X] - (y - ty) *
				(*(double *)pointarray - pointarray[numverts - 1][X]) /
				(*p - y)) >= tx);
		}
	}

	stop = pointarray[numverts];

	for (y = *p, p += 2; p < stop; y = *p, p += 2)
	{
		if (y >= ty)
		{
			while ((p < stop) && (*p >= ty))
				p += 2;
			if (p >= stop)
				break;
			if ((xflag0 = (*(p - 3) >= tx)) == (*(p - 1) >= tx))
			{
				if (xflag0)
					crossings++;
			} else
			{
				crossings += ((*(p - 3) - (*(p - 2) - ty) *
					(*(p - 1) - *(p - 3)) /
					(*p - *(p - 2))) >= tx);
			}
		} else
		{
			while ((p < stop) && (*p < ty))
				p += 2;
			if (p >= stop)
				break;
			if ((xflag0 = (*(p - 3) >= tx)) == (*(p - 1) >= tx))
			{
				if (xflag0)
					crossings++;
			} else
			{
				crossings += ((*(p - 3) - (*(p - 2) - ty) *
					(*(p - 1) - *(p - 3)) /
					(*p - *(p - 2))) >= tx);
			}
		}
	}
	return(crossings & 1);
}

static	VOID
servererr DECL1C(char *, msg)
{
	printf("Content-type: text/html\n\n");
	printf("<HTML><HEAD><TITLE>Mapping server error</TITLE></HEAD>\n");
	printf("<BODY><H1>Mapping server error</H1>\n");
	printf("The mapping server encountered an error:<P>\n");
	printf("%s", msg);
	printf("</BODY></HTML>\n");
	exit(1);
}

static	int
isname DECL1(int, c)
{
	return(!isspace(c));
}

