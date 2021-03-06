/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdbool.h>

#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<fnmatch.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */

#include	"malloc.h"
#include	"path.h"

typedef	struct	mime
{
	char		type[BUFSIZ], ext[BUFSIZ], icon[BUFSIZ],
			alt[BUFSIZ], small[BUFSIZ];
	struct	mime	*next;
} mime;

typedef struct	exlist
{
	const char	*pattern;
	struct	exlist	*next;
} exlist;

static	int	show_type = 1;
static	bool	show_size = true, show_back = true, force_overwrite = false;
static	size_t	max_filename = 0, max_mimetype = 0, max_mimealt = 0,
				max_mimeshort = 0;
static	mime	*mimes;
static	const char	*mimefile;

static	void	usage			(void) NORETURN;
static	void	loadmime		(const char * const);
static	const	char	*encode		(const char * const) WARNUNUSED;
static	const	char	*neatsize	(off_t) WARNUNUSED;
static	const	mime	*findmime	(const char * const) WARNUNUSED;

static	void
usage()
{
	fprintf(stderr,
		"Usage: xsindex [-b] [-f] [-m mimefile] [-s] [-t number] [-x pattern] title\n");
	fprintf(stderr, "   -b           Do not create a `back' link (..)\n");
	fprintf(stderr, "   -f           Do not ask whether to overwrite %s\n",
		INDEX_HTML);
	fprintf(stderr, "   -m mimefile  Use your own mime.index file\n");
	fprintf(stderr, "                (default is %s)\n", mimefile);
	fprintf(stderr, "   -s           Do not give size of each file\n");
	fprintf(stderr, "   -t number    Specify `file type' field options:\n");
	fprintf(stderr, "                   1 - Full mime type\n");
	fprintf(stderr, "                   2 - Short mime type\n");
	fprintf(stderr, "                   3 - Do not give types\n");
	fprintf(stderr, "   -x pattern   Give a filename or pattern "
		"for what should not be listed\n");
	fprintf(stderr, "   title        Title of the %s page\n", INDEX_HTML);
	fprintf(stderr, "                Use \"'s if it's more than one word\n");
	exit(1);
}

static	void
loadmime(const char * const name)
{
	FILE		*input;
	char		buffer[BUFSIZ], *end;
	mime		*new;

	mimes = NULL;
	if (!(input = fopen(name, "r")))
		err(1, "fopen(`%s')", name);
	while (fgets(buffer, BUFSIZ, input))
	{
		if (strchr(buffer, '#'))
			*strchr(buffer, '#') = 0;
		end = strchr(buffer, '\0');
		while ((end > buffer) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (!buffer[0])
			continue;
		MALLOC(new, mime, 1);
		if (sscanf(buffer, "%s %s %s %s %[^\n]\n", new->type,
			new->ext, new->icon, new->alt, new->small) != 5)
		{
			fprintf(stderr, "Cannot parse line `%s'", buffer);
			continue;
		}
		new->next = mimes; mimes = new;
	}
	fclose(input);
	if (!mimes)
		errx(1, "Empty mime.index file: you need at least a default!");
}

static	const	char	*
encode(const char * const what)
{
	size_t		len;
	static	char	buffer[BUFSIZ];

	buffer[0] = '\0';
	for (const char *p = what; (len = strcspn(p, "<>&\"")); p += len + 1)
	{
		if (strlen(buffer) + len < BUFSIZ)
			strncat(buffer, p, len);
		if (!p[len])
			break;
		switch (p[len])
		{
		case '<':
			strlcat(buffer, "&lt;", BUFSIZ);
			break;
		case '>':
			strlcat(buffer, "&gt;", BUFSIZ);
			break;
		case '&':
			strlcat(buffer, "&amp;", BUFSIZ);
			break;
		case '"':
			strlcat(buffer, "&quot;", BUFSIZ);
			break;
		default:
			/* do nothing */;
		}
	}
	return (buffer);
}

static	const	char	*
neatsize(off_t size)
{
	static	char	buffer1[BUFSIZ];
	char		buffer2[BUFSIZ];

	buffer1[0] = 0;
	while (size)
	{
		const off_t temp = size / 1000;
		if (temp)
			snprintf(buffer2, BUFSIZ, "%03" PRIoff ",%s",
				size % 1000, buffer1);
		else
			snprintf(buffer2, BUFSIZ, "%" PRIoff ",%s",
				size % 1000, buffer1);
		strlcpy(buffer1, buffer2, BUFSIZ);
		size = temp;
	}
	if (buffer1[0])
		buffer1[strlen(buffer1) - 1] = 0;
	else
		strlcpy(buffer1, "0", BUFSIZ);
	return (buffer1);
}

static	const	mime	*
findmime(const char * const ext)
{
	const	mime	*search;
	const	char	*end;

	if (!strcmp(ext, ".."))
		end = "..";
	else if (!strcmp(ext, ".directory."))
		end = ".directory.";
	else if ((end = strrchr(ext, '.')))
		end++;
	else
		end = "txt";

	for (search = mimes; search; search = search->next)
		if (!strcasecmp(search->ext, end))
			break;
	return search ? search : mimes;
}

int
main(int argc, char **argv)
{
	int			option, amount, count;
	char			**listing, buffer[BUFSIZ];
	FILE			*output, *ls;
	struct	stat		statbuf;
	const	mime		*search;
	exlist			*exclude, *exhead;

	exclude = NULL;
	mimefile = MIME_INDEX;
	while ((option = getopt(argc, argv, "bfm:st:x:")) != EOF)
	{
		switch(option)
		{
		case 'b':
			show_back = false;
			break;
		case 'f':
			force_overwrite = true;
			break;
		case 'm':
			mimefile = optarg;
			break;
		case 's':
			show_size = false;
			break;
		case 't':
			show_type = atoi(optarg);
			if ((show_type < 1) || (show_type > 3))
			{
				warnx("Invalid argument to -t");
				usage();
			}
			break;
		case 'x':
			MALLOC(exhead, exlist, 1);
			exhead->next = exclude;
			exhead->pattern = optarg;
			exclude = exhead;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1)
		usage();

	loadmime(mimefile);

	if (!(ls = popen("ls -a", "r")))
		err(1, "popen(`ls -a', `r')");
	amount = 0;
	MALLOC(listing, char *, 16);
	while (fgets(buffer, BUFSIZ, ls))
	{
		bool skip = false;

		if (buffer[0] && (buffer[strlen(buffer) - 1] < ' '))
			buffer[strlen(buffer) - 1] = 0;
		if (!strcmp(buffer, ".") || !strcmp(buffer, INDEX_HTML) ||
				!strncmp(buffer, ".xs", 3) ||
				!strcmp(buffer, NOXS_FILE))
			continue;
		if ((strlen(buffer) >= 6) &&
			(!strcmp(strchr(buffer, '\0') - 6, ".redir")))
			continue;
		if (!strcmp(buffer, "..") && !show_back)
			continue;
		for (exhead = exclude; exhead; exhead = exhead->next)
			if (fnmatch(exhead->pattern, buffer, 0) != FNM_NOMATCH)
			{
				skip = true;
				printf("b %s p %s\n", buffer, exhead->pattern);
				break;
			}
		if (skip)
			continue;
		STRDUP(listing[amount], buffer);
		if (max_filename < strlen(listing[amount]))
			max_filename = strlen(listing[amount]);
		if (!((amount + 1) & 0xf))
			REALLOC(listing, char *, amount + 17);
		if (stat(listing[amount], &statbuf))
			err(1, "stat(`%s')", listing[amount]);
		if (S_ISDIR(statbuf.st_mode))
			search = findmime(".directory.");
		else
			search = findmime(listing[amount]);
		if (max_mimealt < strlen(search->alt))
			max_mimealt = strlen(search->alt);
		if (max_mimetype < strlen(search->type))
			max_mimetype = strlen(search->type);
		if (max_mimeshort < strlen(search->small))
			max_mimeshort = strlen(search->small);
		amount++;
	}
	pclose(ls);

	if (!force_overwrite && !access(INDEX_HTML, F_OK))
	{
		printf("A file called %s already exists.\n", INDEX_HTML);
		printf("Do you want to overwrite it (y/n)? ");
		fflush(stdout);
		if (!fgets(buffer, BUFSIZ, stdin) || strcmp(buffer, "y\n"))
			errx(1, "Cancelled on user's request");
	}
	remove(INDEX_HTML);
	if (!(output = fopen(INDEX_HTML, "w")))
		err(1, "fopen(%s)", INDEX_HTML);
	fprintf(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf(output, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
	fprintf(output, "<html><head><title>%s</title></head><body>\n",
		argc ? argv[0] : "directory listing");
	fprintf(output, "<h1>%s</h1>\n<hr />\n<pre>",
		argc ? argv[0] : "directory listing");

	for (count = 0; count < amount; count++)
	{
		if (stat(listing[count], &statbuf))
			err(1, "stat(`%s')", listing[count]);
		if (strcmp(listing[count], "..") && S_ISDIR(statbuf.st_mode))
			search = findmime(".directory.");
		else
			search = findmime(listing[count]);
		fprintf(output, "<a href=\"%s\">", encode(listing[count]));
		fprintf(output, "<img src=\"%s\" ", encode(search->icon));
		fprintf(output, "alt=\"[%s]%*.*s\" />", encode(search->alt),
			(int)(max_mimealt - strlen(search->alt)),
			(int)(max_mimealt - strlen(search->alt)), "");
		fprintf(output, "</a>  ");
		fprintf(output, "<a href=\"%s\">", encode(listing[count]));
		fprintf(output, "%s</a>%*.*s    ", encode(listing[count]),
			(int)(max_filename - strlen(listing[count])),
			(int)(max_filename - strlen(listing[count])), "");
		switch(show_type)
		{
		case 1:
			fprintf(output, "%-*.*s", (int)max_mimetype, (int)max_mimetype,
				search->type);
			break;
		case 2:
			fprintf(output, "%-*.*s", (int)max_mimeshort, (int)max_mimeshort,
				search->small);
			break;
		default:
			break;
		}
		if (show_size && (statbuf.st_mode & S_IFREG))
			fprintf(output, "   %11.11s",
				neatsize(statbuf.st_size));
		fprintf(output, "\n");
	}
	fprintf(output, "</pre></body></html>\n");
	fclose(output);
	printf("`%s' is now ready...\n", INDEX_HTML);
	return 0;
}
