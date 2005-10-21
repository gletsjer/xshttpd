#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */

#include	"mystring.h"
#include	"mygetopt.h"

typedef	struct	mime
{
	struct	mime	*n;
	char		type[BUFSIZ], ext[BUFSIZ], icon[BUFSIZ],
			alt[BUFSIZ], small[BUFSIZ];
} mime;

static	int	show_size = 1, show_type = 1, show_back = 1, force_overwrite = 0;
static	size_t	max_filename = 0, max_mimetype =0, max_mimealt = 0,
				max_mimeshort = 0;
static	char	mimefile[XS_PATH_MAX];
static	mime	*mimes;

static	void	usage			(void);
static	void	loadmime		(const char *);
static	const	char	*encode		(const char *);
static	const	char	*neatsize	(long);
static	const	mime	*findmime	(const char *);

static	void
usage()
{
	fprintf(stderr,
		"Usage: xsindex [-b] [-f] [-m mimefile] [-s] [-t number] title\n");
	fprintf(stderr, "   -b           Do not create a `back' link (..)\n");
	fprintf(stderr, "   -f           Do not ask whether to overwrite %s\n",
		INDEX_HTML);
	fprintf(stderr, "   -m mimefile  Use your own mime.index file\n");
	fprintf(stderr, "                (default is %s/mime.index)\n",
		HTTPD_ROOT);
	fprintf(stderr, "   -s           Do not give size of each file\n");
	fprintf(stderr, "   -t number    Specify `file type' field options:\n");
	fprintf(stderr, "                   1 - Full mime type\n");
	fprintf(stderr, "                   2 - Short mime type\n");
	fprintf(stderr, "                   3 - Do not give types\n");
	fprintf(stderr, "   title        Title of the %s page\n", INDEX_HTML);
	fprintf(stderr, "                Use \"'s if it's more than one word\n");
}

static	void
loadmime(const char *name)
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
		end = buffer + strlen(buffer);
		while ((end > buffer) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (!buffer[0])
			continue;
		if (!(new = (mime *)malloc(sizeof(mime))))
			errx(1, "Out of memory in loadmime()");
		if (sscanf(buffer, "%s %s %s %s %[^\n]\n", new->type,
			new->ext, new->icon, new->alt, new->small) != 5)
		{
			fprintf(stderr, "Cannot parse line `%s'", buffer);
			continue;
		}
		new->n = mimes; mimes = new;
	}
	fclose(input);
	if (!mimes)
		errx(1, "Empty mime.index file: you need at least a default!");
}

static	const	char	*
encode(const char *what)
{
	size_t		len;
	const char	*p;
	static	char	buffer[BUFSIZ];

	buffer[0] = '\0';
	for (p = what; (len = strcspn(p, "<>&\"")); p += len + 1)
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
neatsize(long size)
{
	long		temp;
	static	char	buffer1[BUFSIZ];
	char		buffer2[BUFSIZ];

	buffer1[0] = 0;
	while (size)
	{
		temp = size / 1000;
		if (temp)
			snprintf(buffer2, BUFSIZ, "%03d,%s",
				(int)(size % 1000), buffer1);
		else
			snprintf(buffer2, BUFSIZ, "%d,%s",
				(int)(size % 1000), buffer1);
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
findmime(const char *ext)
{
	const	mime	*search;
	const	char	*end;

	if (!strcmp(ext, ".."))
	{
		end = "..";
	} else if (!strcmp(ext, ".directory."))
	{
		end = ".directory.";
	} else
	{
		end = strrchr(ext, '.');
		end = (end ? (end + 1) : "txt");
	}
	search = mimes;
	while (search)
	{
		if (!strcasecmp(search->ext, end))
			break;
		search = search->n;
	}
	if (!search)
		search = mimes;
	return(search);
}

int
main(int argc, char **argv)
{
	int			option, amount, count;
	char			**listing, buffer[BUFSIZ];
	FILE			*output, *ls;
	struct	stat		statbuf;
	const	mime		*search;

	snprintf(mimefile, XS_PATH_MAX, "%s/mime.index", HTTPD_ROOT);
	while ((option = getopt(argc, argv, "bfm:st:")) != EOF)
	{
		switch(option)
		{
		case 'b':
			show_back = 0;
			break;
		case 'f':
			force_overwrite = 1;
			break;
		case 'm':
			strlcpy(mimefile, optarg, XS_PATH_MAX);
			break;
		case 's':
			show_size = 0;
			break;
		case 't':
			show_type = atoi(optarg);
			if ((show_type < 1) || (show_type > 3))
			{
				usage();
				errx(1, "Invalid argument to -t");
			}
			break;
		default:
			usage();
			exit(1);
		}
	}
	if (optind != (argc - 1))
	{
		usage();
		exit(1);
	}

	loadmime(mimefile);

	if (!(ls = popen("ls -a", "r")))
		err(1, "popen(`ls -a', `r')");
	amount = 0;
	if (!(listing = (char **)malloc(16 * sizeof(char *))))
		errx(1, "Out of memory");
	while (fgets(buffer, BUFSIZ, ls))
	{
		if (buffer[0] && (buffer[strlen(buffer) - 1] < ' '))
			buffer[strlen(buffer) - 1] = 0;
		if (!strcmp(buffer, ".") || !strcmp(buffer, INDEX_HTML) ||
			!strcmp(buffer, ".xsuid") || !strcmp(buffer, ".noxs") ||
			!strcmp(buffer, AUTHFILE))
			continue;
		if ((strlen(buffer) >= 6) &&
			(!strcmp(buffer + strlen(buffer) - 6, ".redir")))
			continue;
		if (!strcmp(buffer, "..") && !show_back)
			continue;
		if (!(listing[amount] = (char *)strdup(buffer)))
			errx(1, "Out of memory");
		if (max_filename < strlen(listing[amount]))
			max_filename = strlen(listing[amount]);
		if (!((amount + 1) & 0xf))
		{
			if (!(listing = (char **)realloc(listing,
				(amount + 17) * sizeof(char *))))
				errx(1, "Out of memory");
		}
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
	/* maybe add this when it actually validates...
	fprintf(output, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 "
		"Transitional//EN\"\n"
		"\t\"http://www.w3c.org/TR/html4/loose.dtd\">\n");
	 */
	fprintf(output, "<HTML><HEAD><TITLE>%s</TITLE></HEAD><BODY>\n",
		argv[optind]);
	fprintf(output, "<H1>%s</H1><HR><PRE>\n", argv[optind]);

	for (count = 0; count < amount; count++)
	{
		if (stat(listing[count], &statbuf))
			err(1, "stat(`%s')", listing[count]);
		if (strcmp(listing[count], "..") && S_ISDIR(statbuf.st_mode))
			search = findmime(".directory.");
		else
			search = findmime(listing[count]);
		fprintf(output, "<A HREF=\"%s\">", encode(listing[count]));
		fprintf(output, "<IMG SRC=\"%s\" ", encode(search->icon));
		fprintf(output, "ALT=\"[%s]%*.*s\">", encode(search->alt),
			(int)(max_mimealt - strlen(search->alt)),
			(int)(max_mimealt - strlen(search->alt)), "");
		fprintf(output, "</A>  ");
		fprintf(output, "<A HREF=\"%s\">", encode(listing[count]));
		fprintf(output, "%s</A>%*.*s    ", encode(listing[count]),
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
				neatsize((long)(statbuf.st_size)));
		fprintf(output, "\n");
	}
	fprintf(output, "</PRE></BODY></HTML>\n");
	fclose(output);
	printf("`%s' is now ready...\n", INDEX_HTML);
	return 0;
}
