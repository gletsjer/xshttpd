/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: gfxcount.c,v 1.5 2001/05/22 12:19:29 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */
#include	<errno.h>
#include	<fcntl.h>

#include	"mystring.h"

#ifdef		PATH_PPMTOGIF
#ifndef		NOFORWARDS
static	VOID	error			PROTO((const char *, const char *));
static	VOID	loaddigit		PROTO((int));
static	VOID	loadfont		PROTO((void));
static	VOID	buildpicture		PROTO((void));
#endif		/* NOFORWARDS */

typedef	struct
{
	int		size_x, size_y;
	char		*fontdata;
} font;

static	const	char	*pathtranslated, *querystring;
static	char		dirname[XS_PATH_MAX], filename[XS_PATH_MAX];
static	font		digit[10];
static	int		max_x, max_y;

static	VOID
error DECL2CC(char *, status, char *, message)
{
	printf("Status: %s\r\n", status);
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML><HEAD><TITLE>%s</TITLE></HEAD>\n", status);
	printf("<BODY><H1>%s</H1>\n%s\n", status, message);
	printf("</BODY></HTML>\n");
	exit(1);
}

static	VOID
loaddigit DECL1(int, num)
{
	FILE		*file;
	char		buffer[BUFSIZ], words[4][BUFSIZ], *search;
	int		word, size;

	sprintf(filename, "%s%c.ppm", dirname, num + '0');
	if (!(file = fopen(filename, "r")))
	{
		sprintf(buffer, "Could not read digit from file `%s': %s",
			filename, strerror(errno));
		error("404 Could not read font data", buffer);
	}
	word = 0; words[0][0] = words[1][0] = words[2][0] = words[3][0] = 0;
	while (word < 4)
	{
		if (!fgets(buffer, BUFSIZ, file))
		{
			sprintf(buffer, "Font data in file `%s' is corrupt",
				filename);
			error("500 Could not read font data", buffer);
		}
		if ((search = strchr(buffer, '#')))
			*search = 0;
		search = buffer + strlen(buffer);
		while ((search > buffer) && (*(search - 1) <= ' '))
			*(--search) = 0;
		if (search == buffer)
			continue;
		search = buffer;
		while ((*search == ' ') || (*search == '\t'))
			search++;
		while (*search)
		{
			sprintf(words[word], "%s%c", words[word], *search);
			if ((*search == ' ') || (*search == '\t'))
			{
				search++; word++;
				while ((*search == ' ') || (*search == '\t'))
					search++;
			} else
				search++;
		}
		word++;
	}
	if (strcmp("P6", words[0]))
	{
		sprintf(buffer, "The image in file `%s' is not a PPM file",
			filename);
		error("500 Invalid image type", buffer);
	}
	if ((digit[num].size_x = atoi(words[1])) <= 0)
	{
		sprintf(buffer, "The image in file `%s' has an invalid X size",
			filename);
		error("500 Corrupt image X header", buffer);
	}
	if ((digit[num].size_y = atoi(words[2])) <= 0)
	{
		sprintf(buffer, "The image in file `%s' has an invalid Y size",
			filename);
		error("500 Corrupt image Y header", buffer);
	}
	if (strcmp("255", words[3]))
	{
		sprintf(buffer, "The image in file `%s' has an invalid depth",
			filename);
		error("500 Corrupt image depth header", buffer);
	}
	size = digit[num].size_x * digit[num].size_y * 3;
	if (!(digit[num].fontdata = (char *)malloc(size)))
		error("500 Out of memory",
			"There was not enough memory to load the images");
	if (fread(digit[num].fontdata, size, 1, file) != 1)
		error("500 Error reading actual font data",
			"The image body could not be successfully read");
	fclose(file);
}

static	VOID
loadfont DECL0
{
	int		number;
	const	char	*search;

	max_x = max_y = 0;
	for (number = 0; number < 10; number++)
	{
		digit[number].size_x = digit[number].size_y = 0;
		digit[number].fontdata = NULL;
	}
	for (search = querystring; *search; search++)
	{
		number = *search - '0';
		if ((number < 0) || (number > 9))
			error("403 Incorrect usage",
				"Non-digits encountered in argument");
		if (!digit[number].fontdata)
		{
			loaddigit(number);
			if (max_y < digit[number].size_y)
				max_y = digit[number].size_y;
		}
		max_x += digit[number].size_x;
	}
}

static	VOID
buildpicture DECL0
{
	const	char	*search;
	char		*data, header[1024];
	int		number, pos_x, y, font_width, fd, p[2];

	if (!(data = (char *)malloc(max_x * max_y * 3)))
		error("500 Out of memory",
			"Not enough memory to build picture");
	bzero(data, max_x * max_y * 3);
	pos_x = 0;
	for (search = querystring; *search; search++)
	{
		number = *search - '0';
		font_width = digit[number].size_x;
		for (y = 0; y < digit[number].size_y; y++)
		{
			bcopy(digit[number].fontdata + (3 * y * font_width),
				data + 3 * ((y * max_x) + pos_x),
				3 * font_width);
		}
		pos_x += font_width;
	}
	fflush(stdout);
	if (pipe(p))
		error("500 Could not create pipe",
			"Could not create pipe for interprocess communication");
	switch(fork())
	{
	case -1:
		error("500 Could not fork()",
			"Could not create new process to make GIF file");
	case 0:
		close(p[1]); dup2(p[0], 0);
		if (p[0] != 0)
			close(p[0]);
		if ((fd = open(BITBUCKETNAME, O_WRONLY, S_IWUSR | S_IRUSR)) < 0)
			error("500 Cannot open temp file",
				"Could not open temporary file");
		if (fd != 2)
		{
			if (dup2(fd, 2) == -1)
				error("500 dup2() failed",
					"Could not duplicate file descriptor");
			close(fd);
		}
		printf("Content-type: image/gif\r\n\r\n");
		fflush(stdout);
		execl(PATH_PPMTOGIF, "ppmtogif", "-transparent", "#000000",
			NULL);
		error("500 Could not start ppmtogif",
			"Could not start PPM to GIF converter");
	default:
		close(p[0]);
		sprintf(header, "P6\n%d %d\n255\n", max_x, max_y);
		write(p[1], header, strlen(header));
		write(p[1], data, max_x * max_y * 3);
	}
	exit(0);
}

extern	int
main DECL2(int, argc, char **, argv)
{
	struct	stat	statbuf;
	char		buffer[XS_PATH_MAX];

	alarm(240);
	pathtranslated = getenv("PATH_TRANSLATED");
	strcpy(dirname, pathtranslated ? pathtranslated : "");
	if (!dirname[0])
		sprintf(dirname, "%s/gfxcount/digital", HTTPD_ROOT);
	if (!strncmp(dirname, "/fonts/", 7))
	{
		sprintf(buffer, "%s/gfxcount/%s", HTTPD_ROOT, dirname + 7);
		strcpy(dirname, buffer);
	}
	if (dirname[0] && (dirname[strlen(dirname) - 1] != '/'))
	{
		if (!stat(dirname, &statbuf) && (S_ISDIR(statbuf.st_mode)))
			strcat(dirname, "/");
	}
	if (!(querystring = getenv("QUERY_STRING")) || !(*querystring))
		error("403 Illegal calling method",
			"You must supply a number as a query argument");
	loadfont();
	buildpicture();
	(void)argc;
	(void)argv;
	exit(0);
}

#else		/* Not PATH_PPMTOGIF */

extern	int
main DECL2(int, argc, char **, argv)
{
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML><HEAD><TITLE>No can do</TITLE></HEAD>\n");
	printf("<H1>No can do</H1>Regrettably, this operation\n");
	printf("can not (yet) be performed, because the system lacks\n");
	printf("some necessary programs.</BODY></HTML>\n");
	exit(1);
}
#endif		/* PATH_PPMTOGIF */
