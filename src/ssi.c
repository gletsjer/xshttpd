/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>

#include	<stdio.h>
#include	<time.h>
#include	<unistd.h>
#include	<errno.h>
#include	<signal.h>
#include	<pwd.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<fcntl.h>
#include	<stdlib.h>
#include	<string.h>

#include	<sys/wait.h>
#include	<sys/resource.h>

#include	"htconfig.h"
#include	"ssi.h"
#include	"httpd.h"
#include	"extra.h"
#include	"path.h"
#include	"ssl.h"
#include	"convert.h"
#include	"xscounter.h"
#include	"methods.h"
#include	"decode.h"
#include	"malloc.h"

typedef	enum
{
	MODE_ALL, MODE_GFX_ALL,
	MODE_TODAY, MODE_GFX_TODAY,
	MODE_MONTH, MODE_GFX_MONTH,
	MODE_RESET
} countermode;

static	bool	xsc_initdummy		(off_t *);
static	bool	xsc_initcounter		(const char *, off_t *);
static	bool	xsc_counter		(countermode, const char *, off_t *);
static	int	call_counter		(countermode, int, char * const * const, off_t *);
static	int	parse_values		(const char * const, char **, size_t);
static	int	dir_count_total		(int, char **, off_t *);
static	int	dir_count_total_gfx	(int, char **, off_t *);
static	int	dir_count_today		(int, char **, off_t *);
static	int	dir_count_today_gfx	(int, char **, off_t *);
static	int	dir_count_month		(int, char **, off_t *);
static	int	dir_count_month_gfx	(int, char **, off_t *);
static	int	dir_count_reset		(int, char **, off_t *);
static	int	dir_date		(int, char **, off_t *);
static	int	dir_date_format		(int, char **, off_t *);
static	int	dir_exec		(int, char **, off_t *);
static	int	dir_include_file	(int, char **, off_t *);
static	int	dir_last_mod		(int, char **, off_t *);
static	int	dir_run_cgi		(int, char **, off_t *);
static	int	dir_echo		(int, char **, off_t *);
static	int	dir_echo_obsolete	(int, char **, off_t *);
static	int	dir_if			(int, char **, off_t *);
static	int	dir_if_not		(int, char **, off_t *);
static	int	dir_else		(int, char **, off_t *);
static	int	dir_endif		(int, char **, off_t *);
static	int	dir_switch		(int, char **, off_t *);
static	int	dir_endswitch	(int, char **, off_t *);
static	int	dir_case		(int, char **, off_t *);
static	bool	print_enabled		(void);
static	int	parsedirectives		(const char *, off_t *);
static	int	sendwithdirectives_internal (int, off_t *);

#define		MAXINCLUDES	16
#define		CONDKEYWORDS	16
#define		SETVARIABLES	200
#define		SSIARGUMENTS	100
static	bool	cnt_readbefore;
static	unsigned int	ssioutput, numincludes;
static	char	ssiarray[CONDKEYWORDS];
static	char	*switchstr;
static	int	setvarlen;
static	char	*setvars[SETVARIABLES];

static	bool
xsc_initdummy(off_t *size)
{
	int		fd;
	countstr	dummy;

	if ((fd = open(CNT_DATA, O_WRONLY | O_CREAT,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		*size += secprintf("[Failed to create dummies: %s]\n",
			strerror(errno));
		return false;
	}

	memset(dummy.filename, 1, sizeof(dummy.filename) - 1);
	dummy.filename[0] = XSCOUNT_VERSION;
	dummy.filename[sizeof(dummy.filename) - 1] = 0;
	dummy.total = dummy.today = dummy.month = 0;
	dummy.lastseen = (time_t)0;
	if (write(fd, &dummy, sizeof(dummy)) != sizeof(dummy))
	{
		*size += secprintf("[Failed to write dummy file: %s]\n",
			strerror(errno));
		close(fd);
		return false;
	}

	memset(dummy.filename, 255, sizeof(dummy.filename)-1);
	dummy.filename[sizeof(dummy.filename) - 1] = 0;
	if (write(fd, &dummy, sizeof(dummy)) != sizeof(dummy))
	{
		*size += secprintf("[Failed to write dummy file: %s]\n",
			strerror(errno));
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

static	bool
xsc_initcounter(const char *filename, off_t *size)
{
	int		fd, fd2;
	bool		done;
	unsigned int	retry;
	countstr	counter, counter2;
	char		datafile[XS_PATH_MAX];
	const char * const	lockfile = CNT_LOCK;

	strlcpy(datafile, CNT_DATA, XS_PATH_MAX);
	if ((fd = open(datafile, O_RDONLY,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		*size += secprintf("[Could not open the counter file: %s]\n",
			strerror(errno));
		return false;
	}
	retry = 0;
	while ((fd2 = open(lockfile, O_WRONLY | O_CREAT | O_EXCL,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0 && retry++ < 5)
	{
		usleep(300);
	}
	if (fd2 < 0)
	{
		*size += secprintf("[Failed to create temporary file: %s]\n",
			strerror(errno));
		close(fd);
		return false;
	}

	done = false;
	strlcpy(counter2.filename, filename, sizeof(counter2.filename));
	counter2.total = counter2.today = counter2.month = 0;
	counter2.lastseen = (time_t)0;

	while (read(fd, &counter, sizeof(counter)) == sizeof(counter))
	{
		if ((!done) && (strcmp(counter.filename, filename) > 0))
		{
			if (write(fd2, &counter2, sizeof(counter2)) !=
				sizeof(counter2))
			{
				*size += secprintf("[Failed to write temp file: %s]\n",
					strerror(errno));
				close(fd); close(fd2); remove(lockfile);
				return false;
			}
			done = true;
		}
		if (write(fd2, &counter, sizeof(counter)) != sizeof(counter))
		{
			*size += secprintf("[Failed to write temp file: %s]\n",
				strerror(errno));
			close(fd); close(fd2); remove(lockfile);
			return false;
		}
	}

	if (!done)
	{
		if (write(fd2, &counter2, sizeof(counter2)) != sizeof(counter2))
			*size += secprintf("[Failed to write temp file: %s]\n",
				strerror(errno));
	}
	close(fd); close(fd2);
	if (rename(lockfile, datafile))
	{
		*size += secprintf("[Could not rename counter file: %s]\n",
			strerror(errno));
		remove(lockfile);
		return false;
	}
	remove(lockfile);
	return true;
}

void
counter_versioncheck()
{
	int			fd;
	char			xscount_version;
	const char * const	counterfile = CNT_DATA;

	if ((fd = open(counterfile, O_RDONLY, 0)) < 0)
		/* no data yet: that's fine */
		return;

	if (read(fd, &xscount_version, sizeof(char)) != sizeof(char))
		errx(1, "XS count data corrupt (%s)", counterfile);
	close(fd);

	if (XSCOUNT_VERSION == (int)xscount_version)
		return;
	else if (XSCOUNT_VERSION > (int)xscount_version)
		errx(1, "XS count data in old format: run reformatxs first!");
	else
		errx(1, "XS count data corrupt (newer version?)");
	/* NOTREACHED */
}

static	bool
xsc_counter(countermode mode, const char * const args, off_t *size)
{
	int			fd = -1, total, x, y, z, comp;
	bool			already = false;
	static	countstr	counter;
	char			*p, filename[sizeof(counter.filename)];

	if (env.request_uri)
		strlcpy(filename, env.request_uri, sizeof(filename));
	else
		*filename = '\0';

	if ((p = strchr(filename, '?')))
		*p = '\0';

	if (cnt_readbefore)
		goto ALREADY;
	cnt_readbefore = true;

	counter.total = counter.today = counter.month = 0;
	counter.lastseen = (time_t)0;

	REOPEN:
	if ((fd = open(CNT_DATA, O_RDWR,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		if (!xsc_initdummy(size))
			return false;
		goto REOPEN;
	}

	if ((total = lseek(fd, (off_t)0, SEEK_END)) == -1)
	{
		*size += secprintf("[Could not find end of the counter file: %s]\n",
			strerror(errno));
		close(fd);
		return false;
	}

	total /= sizeof(countstr);
	if (total < 2)
	{
		close(fd);
		if (!xsc_initdummy(size))
			return false;
		goto REOPEN;
	}

	x = 0; z = total - 1; y = z / 2; comp = 1;
	while ((x < (z-1)) && (comp))
	{
		y = (x + z) / 2;
		if (lseek(fd, (off_t)(y * sizeof(countstr)), SEEK_SET) == -1)
		{
			*size += secprintf("[Could not seek in counter file: %s]\n",
				strerror(errno));
			close(fd);
			return false;
		}
		if (read(fd, &counter, sizeof(countstr)) != sizeof(countstr))
		{
			*size += secprintf("[Could not read counter file: %s]\n",
				strerror(errno));
			close(fd);
			return false;
		}
		if ((comp = strncmp(filename, counter.filename, sizeof(counter.filename))) < 0)
			z = y;
		else
			x = y;
	}

	if (comp)
	{
		close(fd);
		if (already)
		{
			*size += secprintf("[Failed to create new counter]\n");
			return false;
		}
		already = true;
		if (!xsc_initcounter(filename, size))
			return false;
		goto REOPEN;
	}

	counter.total++; counter.today++; counter.month++;
	counter.lastseen = time(NULL);
	if (lseek(fd, (off_t)(y * sizeof(countstr)), SEEK_SET) == -1)
	{
		*size += secprintf("[Could not seek in counter file: %s]\n",
			strerror(errno));
		close(fd);
		return false;
	}
	if (mode == MODE_RESET)
	{
		counter.total = counter.month = counter.today = 0;
		counter.lastseen = (time_t)0;
		if (write(fd, &counter, sizeof(countstr)) != sizeof(countstr))
		{
			*size += secprintf("[Could not update counter file: %s]\n",
				strerror(errno));
			close(fd);
			return false;
		}
		close(fd);
		return true;
	}
	if (write(fd, &counter, sizeof(countstr)) != sizeof(countstr))
	{
		*size += secprintf("[Could not update counter file: %s]\n",
			strerror(errno));
		close(fd);
		return false;
	}
	close(fd);

	ALREADY:
	switch(mode)
	{
	case MODE_ALL:
		*size += secprintf("%d", counter.total);
		break;
	case MODE_GFX_ALL:
		*size += secprintf("<IMG SRC=\"/%s/gfxcount%s?%d\" ALT=\"%d\">",
			current->execdir,
			args ? args : "", counter.total, counter.total);
		break;
	case MODE_TODAY:
		*size += secprintf("%d", counter.today);
		break;
	case MODE_GFX_TODAY:
		*size += secprintf("<IMG SRC=\"/%s/gfxcount%s?%d\" ALT=\"%d\">",
			current->execdir,
			args ? args : "", counter.today, counter.today);
		break;
	case MODE_MONTH:
		*size += secprintf("%d", counter.month);
		break;
	case MODE_GFX_MONTH:
		*size += secprintf("<IMG SRC=\"/%s/gfxcount%s?%d\" ALT=\"%d\">",
			current->execdir,
			args ? args : "", counter.month, counter.month);
		break;
	case MODE_RESET:
		if (counter.total > 0)
			/* This is quite redundant... Let's think of a better way */
			goto REOPEN;
		*size += secprintf("[reset stats counter]");
		break;
	}
	return true;
}

static	int
call_counter(countermode mode, int argc, char * const * const argv, off_t *size)
{
	xs_error_t		ret;
	uid_t			savedeuid;
	gid_t			savedegid;
	const char * const	path = argc ? argv[0] : NULL;

	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); setegid(origegid);
	}
	else
	{
		savedeuid = config.system->userid;
		savedegid = config.system->groupid;
	}
	ret = xsc_counter(mode, path, size) ? ERR_NONE : ERR_CONT;
	if (!origeuid)
	{
		setegid(savedegid); seteuid(savedeuid);
	}
	return(ret);
}

static	int
parse_values(const char * const here, char **mapping, size_t maxsize)
{
	char		*p, *e, *word, *args;
	char * const	end = strstr(here, "-->");
	enum		{ T_INDEX, T_EQUAL, T_VALUE }	expect;
	size_t		mapsize;
	bool		guard;

	if (!end)
		return 0;
	*end = '\0';

	STRDUP(args, here);
	mapsize = 0;
	expect = T_INDEX;
	guard = true;
	for (p = word = args; guard && mapsize < maxsize; p++)
	{
		switch (*p)
		{
		case '=':
			*p = '\0';
			if (*word)
				/* add index */
				STRDUP(mapping[mapsize++], word);
			else if (expect == T_INDEX)
				/* equal without index */
				mapping[mapsize++] = NULL;
			word = p + 1;
			expect = T_VALUE;
			break;
		case '"':
			*p = '\0';
			word = p + 1;
			if ((e = strchr(word, '"')))
			{
				*e = '\0';
				p = e;
				if (expect == T_EQUAL)
				/* word without equal: new index */
					mapping[mapsize++] = NULL;
				/* add index or value */
				STRDUP(mapping[mapsize++], word);
				word = p + 1;
			}
			if (expect == T_VALUE)
				expect = T_INDEX;
			else /* expect == T_INDEX */
				expect = T_EQUAL;
			break;
		case '\0':
			guard = false;
		case ' ':  case '\t':
		case '\r': case '\n':
			*p = '\0';
			if (!*word)
			{
				word++;
				break;
			}
			/* add index or value */
			STRDUP(mapping[mapsize++], word);
			word = p + 1;
			if (expect == T_VALUE)
				expect = T_INDEX;
			else /* expect == T_INDEX */
				expect = T_EQUAL;
			break;
		default:
			if (word == p && expect == T_EQUAL)
			{
				/* word without equal: new index */
				mapping[mapsize++] = NULL;
				expect = T_INDEX;
			}
		}
	}

	*end = '-';
	FREE(args);
	return (int)mapsize;
}

static	int
dir_count_total(int argc, char **argv, off_t *size)
{
	(void)argc;
	(void)argv;
	return(call_counter(MODE_ALL, 0, NULL, size));
}

static	int
dir_count_total_gfx(int argc, char **argv, off_t *size)
{
	return(call_counter(MODE_GFX_ALL, argc, argv, size));
}

static	int
dir_count_today(int argc, char **argv, off_t *size)
{
	(void)argc;
	(void)argv;
	return(call_counter(MODE_TODAY, 0, NULL, size));
}

static	int
dir_count_today_gfx(int argc, char **argv, off_t *size)
{
	return(call_counter(MODE_GFX_TODAY, argc, argv, size));
}

static	int
dir_count_month(int argc, char **argv, off_t *size)
{
	(void)argc;
	(void)argv;
	return(call_counter(MODE_MONTH, 0, NULL, size));
}

static	int
dir_count_month_gfx(int argc, char **argv, off_t *size)
{
	return(call_counter(MODE_GFX_MONTH, argc, argv, size));
}

static	int
dir_count_reset(int argc, char **argv, off_t *size)
{
	return(call_counter(MODE_RESET, argc, argv, size));
}

static	int
dir_date_format(int argc, char **argv, off_t *size)
{
	char	*format, *zone;

	if (!argc)
	{
		*size += secputs("[No parameter to date-format]\n");
		return(ERR_CONT);
	}

	format = zone = NULL;
	for (int i = 0; i < argc; i += 2)
		if (!strcmp(argv[i], "format"))
			format = argv[i + 1];
		else if (!strcmp(argv[i], "zone"))
			zone = argv[i + 1];

	if (!format && !zone)
		format = argv[0];
	if (zone)
		setenv("TZ", zone, 1);
	if (format)
		strlcpy(session.dateformat, format, sizeof session.dateformat);
	(void)size;
	return(ERR_NONE);
}

static	int
dir_date(int argc, char **argv, off_t *size)
{
	int		i;
	char		buffer[MYBUFSIZ];
	const char	*format, *zone;
	char		*ozone;

	format = session.dateformat;
	zone = ozone = NULL;
	for (i = 0; i < argc; i += 2)
		if (!strcmp(argv[i], "format"))
			format = argv[i + 1];
		else if (!strcmp(argv[i], "zone"))
			zone = argv[i + 1];

	if (zone)
	{
		STRDUP(ozone, getenv("TZ"));
		setenv("TZ", zone, 1);
	}
	*size += strftime(buffer, MYBUFSIZ - 1, format, localtimenow());
	if (ozone)
	{
		setenv("TZ", ozone, 1);
		FREE(ozone);
	}
	else if (zone)
		unsetenv("TZ");
	return(secputs(buffer) == EOF ? ERR_QUIT : ERR_NONE);
}

static	int
dir_include_file(int argc, char **argv, off_t *size)
{
	bool		ssi;
	int		fd, ret;
	const	char	*path = NULL;

	if ((numincludes++) > MAXINCLUDES)
	{
		*size += secputs("[Too many include files]\n");
		return(ERR_CONT);
	}
	if (!argc)
	{
		*size += secputs("[No parameter for include-file]\n");
		return(ERR_CONT);
	}

	ssi = true;
	for (int i = 0; i < argc; i += 2)
		if (!strcmp(argv[i], "virtual"))
			/* run as script */
			return dir_run_cgi(1, &argv[i + 1], size);
		else if (!strcmp(argv[i], "file"))
			path = argv[i + 1];
		else if (!strcmp(argv[i], "binary"))
		{
			path = argv[i + 1];
			ssi = false;
		}

	if (!path)
		path = argv[0];

	if ('/' != path[0] || '~' == path[1])
		path = convertpath(path);
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
	{
		char	*escpath = escape(path);
		*size += secprintf("[Error opening file `%s': %s]\n",
			escpath, strerror(errno));
		FREE(escpath);
		return(ERR_CONT);
	}
	if (ssi)
		ret = sendwithdirectives_internal(fd, size);
	else /* dump content directly */
	{
		ssize_t	rlen;
		char	buffer[RWBUFSIZE];

		while ((rlen = read(fd, buffer, RWBUFSIZE)) > 0)
		{
			secwrite(buffer, (size_t)rlen);
			*size += rlen;
		}
		ret = 0;
	}
	numincludes--;
	close(fd);
	return(ret);
}

static	int
dir_last_mod(int argc, char **argv, off_t *size)
{
	const	char	*path;
	char		buffer[MYBUFSIZ], *escpath;
	struct	stat	statbuf;
	struct	tm	*thetime;

	if (argc)
	{
		path = convertpath(argv[0]);
		if (stat(path, &statbuf))
		{
			escpath = escape(path);
			*size += secprintf("[Cannot stat file '%s': %s]\n",
				escpath, strerror(errno));
			FREE(escpath);
			return(ERR_CONT);
		}
		thetime = localtime(&statbuf.st_mtime);
	} else {
		/* previous SSI's may have broken $modtime */
		if ((path = getenv("ORIG_PATH_TRANSLATED")) &&
				!stat(path, &statbuf))
			thetime = localtime(&statbuf.st_mtime);
		if ((path = getenv("SCRIPT_FILENAME")) &&
				!stat(path, &statbuf))
			thetime = localtime(&statbuf.st_mtime);
		else
			thetime = localtimenow();
	}

	strftime(buffer, MYBUFSIZ - 1, session.dateformat, thetime);
	*size += strlen(buffer);
	return(secputs(buffer) == EOF ? ERR_QUIT : ERR_NONE);
}

static	int
dir_exec(int argc, char **argv, off_t *size)
{
	pid_t	child;
	int	status;

	if (!argc)
	{
		*size += secputs("[No parameter for exec]\n");
		return(ERR_CONT);
	}

	if (!strcmp(argv[0], "cgi"))
	{
		*size += secputs("[exec cgi not supported: use run-cgi]\n");
		return(ERR_CONT);
	}
	else if (!strcmp(argv[0], "cmd"))
		/* do nothing */;
	else
	{
		*size += secputs("[exec invalid argument: use exec cmd=..]\n");
		return(ERR_CONT);
	}

	switch ((child = vfork()))
	{
	case 0:
		setenv("PATH", config.scriptpath, 1);
		/* XXX: This needs proper privilege handling,
		 * like run-cgi (rather do_script) offers!
		execl("/bin/sh", "sh", "-c", argv[1], NULL);
		 */
		*size += secputs("[exec not implemented]\n");
		exit(1);
	case -1:
		*size += secprintf("[Execute failed: %s\n", strerror(errno));
		return(ERR_CONT);
	default:
		waitpid(child, &status, 0);
	}
	return(ERR_NONE);
}

static	int
dir_run_cgi(int argc, char **argv, off_t *size)
{
	const char	*querystring;
	bool	oldhead;

	STRDUP(querystring, env.query_string);

	if (!argc)
	{
		*size += secputs("[No parameter for run-cgi]\n");
		return(ERR_CONT);
	}
	oldhead = session.headers;
	session.headers = false;
	do_get(argv[0]);
	session.headers = oldhead;

	/* used to do something like this - which is way more efficient
	 *
	do_script(here, "", "", NULL, 0);
	 */
	if (querystring)
	{
		setenv("QUERY_STRING", querystring, 1);
		env.query_string = getenv("QUERY_STRING");
	}
	if ((env.path_info = getenv("ORIG_PATH_INFO")))
	{
		setenv("PATH_INFO", env.path_info, 1);
		unsetenv("ORIG_PATH_INFO");
	}
	if (getenv("ORIG_PATH_TRANSLATED"))
	{
		setenv("PATH_TRANSLATED", getenv("ORIG_PATH_TRANSLATED"), 1);
		unsetenv("ORIG_PATH_TRANSLATED");
	}
	(void)size;
	return(ERR_NONE);
}

static	int
dir_printenv(int argc, char **argv, off_t *size)
{
	char **p, *c, *v;

	for (p = environ; (c = *p); ++p)
	{
		/* print as html */
		v = escape(c);
		*size += secprintf("%s<br>\n", v);
		FREE(v);
	}
	(void)argc;
	(void)argv;
	return(ERR_NONE);
}

static	int
dir_set(int argc, char **argv, off_t *size)
{
	if (setvarlen + argc > SETVARIABLES)
	{
		*size += secputs("[Too many set arguments]\n");
		return(ERR_CONT);
	}

	for (int i = 0; i < argc; i++, setvarlen++)
		STRDUP(setvars[setvarlen], argv[i]);
	(void)size;
	return ERR_NONE;
}

static	int
dir_echo(int argc, char **argv, off_t *size)
{
	char	*var = NULL, *envvar = NULL, *enc = NULL;
	const	char	*value;

	for (int i = 0; i < argc; i += 2)
	{
		if (!strcmp(argv[i], "var"))
			var = argv[i+1];
		else if (!strcmp(argv[i], "envvar"))
			envvar = argv[i+1];
		else if (!strcmp(argv[i], "encoding"))
			enc = argv[i+1];
		else if (argv[i+1])
			/* ignore unknown index=value argument */
			;
		else
			/* assume old-style var */
			var = argv[i];
	}

	value = getenv(envvar ? envvar : var);
	if (var)
		for (int i = 0; i < setvarlen; i += 2)
			if (setvars[i] && !strcmp(setvars[i], var))
				value = setvars[i + 1];

	if (!value)
		value = "";
	if (enc && !strcmp(enc, "none"))
		*size += secputs(value);
	else if (enc && !strcmp(enc, "url"))
	{
		var = urlencode(value, false);
		*size += secputs(var);
		FREE(var);
	}
	else /* enc = "html" */
	{
		var = escape(value);
		*size += secputs(var);
		FREE(var);
	}
	return(ERR_NONE);
}

static	int
dir_echo_obsolete(int argc, char **argv, off_t *size)
{
	const char	*value = NULL;

	/* argv[0] = ssi name for ssi w/o arguments */
	if (!strcmp(argv[0], "remote-host"))
		value = env.remote_host;
	else if (!strcmp(argv[0], "agent-long"))
		value = getenv("USER_AGENT");
	else if (!strcmp(argv[0], "agent-short"))
		value = getenv("USER_AGENT_SHORT");
	else if (!strcmp(argv[0], "argument"))
		value = env.query_string;
	else if (!strcmp(argv[0], "referer"))
		value = getenv("HTTP_REFERER");

	*size += secputs(value ? value : "[none]");
	(void)argc;
	return(ERR_NONE);
}

static	int
dir_if(int argc, char **argv, off_t *size)
{
	int		i, b;
	const char	*keyword, *value;

	if (argc < 3 || !(keyword = argv[0]) || !(value = argv[2]))
	{
		*size += secputs("[No parameters for if]\n");
		return(ERR_CONT);
	}
	if (ssioutput >= SSIARGUMENTS-1)
	{
		*size += secputs("[Too many nested if statements]\n");
		return(ERR_CONT);
	}
	if (!strcasecmp(keyword, "browser"))
		value = getenv("USER_AGENT");
	else if (!strcasecmp(keyword, "remote-host"))
		value = env.remote_host;
	else if (!strcasecmp(keyword, "remote-name"))
		value = env.remote_host;
	else if (!strcasecmp(keyword, "remote-addr"))
		value = env.remote_addr;
	else if (!strcasecmp(keyword, "argument"))
		value = env.query_string;
	else if (!strcasecmp(keyword, "referer"))
		value = getenv("HTTP_REFERER");
	else if (!strcasecmp(keyword, "var"))
	{
		const char	*var = NULL;

		for (i = 0; i < setvarlen; i += 2)
			if (setvars[i] && !strcmp(setvars[i], argv[1]))
				var = setvars[i + 1];
		value = var ? var : getenv(argv[1]);
	}
	else if (!strcasecmp(keyword, "envvar"))
		value = getenv(argv[1]);
	else
	{
		*size += secputs("[Unknown if subtype]\n");
		return(ERR_CONT);
	}
	/* check all arguments, true if any matches */
	b = 0;
	if (value && *value)
		for (i = 2; i < argc; i += 2)
			if ((b |= match(value, argv[i])))
				break;
	ssiarray[++ssioutput] = b;
	return(ERR_NONE);
}

static	int
dir_if_not(int argc, char **argv, off_t *size)
{
	if (dir_if(argc, argv, size) != ERR_NONE)
		return(ERR_CONT);
	ssiarray[ssioutput] = !ssiarray[ssioutput];
	return(ERR_NONE);
}

static	int
dir_else(int argc, char **argv, off_t *size)
{
	ssiarray[ssioutput] = !ssiarray[ssioutput];
	(void)size;
	(void)argc;
	(void)argv;
	return(ERR_NONE);
}

static	int
dir_endif(int argc, char **argv, off_t *size)
{
	if (!ssioutput)
	{
		*size += secputs("[No if's to endif]\n");
		return(ERR_CONT);
	}
	ssioutput--;
	(void)argc;
	(void)argv;
	return(ERR_NONE);
}

static	int
dir_switch(int argc, char **argv, off_t *size)
{
	if (!argc)
	{
		*size += secputs("[No parameter for switch]\n");
		return(ERR_CONT);
	}
	ssiarray[++ssioutput] = 0;
	STRDUP(switchstr, argv[0]);
	return(ERR_NONE);
}

static	int
dir_endswitch(int argc, char **argv, off_t *size)
{
	dir_endif(argc, argv, size);
	FREE(switchstr);
	return(ERR_NONE);
}

static	int
dir_case(int argc, char **argv, off_t *size)
{
	int	ret;

	if (!argc)
		return(ERR_CONT);

	dir_endif(argc, argv, size);
	argc = 3;
	argv[2] = argv[0];
	argv[1] = NULL;
	argv[0] = switchstr;
	ret = dir_if(argc, argv, size);
	argv[0] = NULL;

	return ret;
}

typedef	struct
{
	const	char	*name;
	int		(*func) (int, char **, off_t *);
	bool		params;
	bool		conditional;
	/* padding */
} directivestype;

static	directivestype	directives[] =
{
	{ "count-total",	dir_count_total,	false,	false	},
	{ "count-total-gfx",	dir_count_total_gfx,	true,	false	},
	{ "count-today",	dir_count_today,	false,	false	},
	{ "count-today-gfx",	dir_count_today_gfx,	true,	false	},
	{ "count-month",	dir_count_month,	false,	false	},
	{ "count-month-gfx",	dir_count_month_gfx,	true,	false	},
	{ "count-reset",	dir_count_reset,	false,	false	},
	{ "date",		dir_date,		true,	false	},
	{ "date-format",	dir_date_format,	true,	false	},
	{ "exec",		dir_exec,		true,	false	},
	{ "include",		dir_include_file,	true,	false	},
	{ "include-file",	dir_include_file,	true,	false	},
	{ "last-modified",	dir_last_mod,		true,	false	},
	{ "last-mod",		dir_last_mod,		true,	false	},
	{ "remote-host",	dir_echo_obsolete,	false,	false	},
	{ "run-cgi",		dir_run_cgi,		true,	false	},
	{ "agent-short",	dir_echo_obsolete,	false,	false	},
	{ "agent-long",		dir_echo_obsolete,	false,	false	},
	{ "argument",		dir_echo_obsolete,	false,	false	},
	{ "printenv",		dir_printenv,		false,	false	},
	{ "referer",		dir_echo_obsolete,	false,	false	},
	{ "set",		dir_set,		true,	false	},
	{ "echo",		dir_echo,		true,	false	},
	{ "if",			dir_if,			true,	true	},
	{ "if-not",		dir_if_not,		true,	true	},
	{ "else",		dir_else,		false,	true	},
	{ "endif",		dir_endif,		false,	true	},
	{ "switch",		dir_switch,		true,	true	},
	{ "endswitch",		dir_endswitch,		false,	true	},
	{ "case",		dir_case,		true,	true	},
	{ NULL,			NULL,			false,	false	}
};

static	bool
print_enabled()
{
	unsigned int	count;

	for (count = 0; count <= ssioutput; count++)
		if (!ssiarray[count])
			return false;

	return true;
}

static	int
parsedirectives(const char * const parse, off_t *size)
{
	const char		*here;
	char	result[MYBUFSIZ], *store;

	store = result; here = parse;
	while (*here)
	{
		bool		printable;
		int		len, argc;
		char		*argv[SSIARGUMENTS];
		directivestype	*directive;

		if ((*here != '<') || strncmp(here + 1, "!--#", 4))
		{
			*(store++) = *(here++);
			continue;
		}
		printable = print_enabled();
		if (store != result)
		{
			if (printable)
			{
				if (secwrite(result, (size_t)(store - result)) < 0)
					return(ERR_QUIT);
				*size += (store - result);
			}
			store = result;
		}
		here += 5;
		len = argc = parse_values(here, argv, SSIARGUMENTS);
		for (directive = directives; directive->name; directive++)
		{
			const char	*search;

			if (len < 1 || strcasecmp(directive->name, argv[0]))
				continue;

			if (directive->params)
			{
				/* remove argv[0..1] */
				FREE(argv[0]);
				for (argc = 0; argc < len - 2; argc++)
					argv[argc] = argv[argc + 2];
			}
			else
				argc = 0;
			if (printable || directive->conditional)
			{
				switch (directive->func(argc, argv, size))
				{
				case ERR_QUIT:
					return(ERR_QUIT);
				case ERR_CONT:
					*size += secputs("[Error parsing directive]\n");
					break;
				}
			}
			if ((search = strstr(here, "-->")))
				here = search + 3;
			break;
		}
		while (argc--)
			FREE(argv[argc]);
		if (!directive->name)
		{
			const char	*search;

			*size += secputs("[Unknown directive]\n");
			if ((search = strstr(here, "-->")))
				here = search + 3;
		}
		else if (!directive->params)
			FREE(argv[0]);
	}

	if (store != result)
	{
		if (print_enabled())
		{
			if (secwrite(result, (size_t)(store - result)) < 0)
				return(ERR_QUIT);
			*size += (store - result);
		}
	}
	return(ERR_NONE);
}

static	int
sendwithdirectives_internal(int fd, off_t *size)
{
	const char	*line;
	FILE		*parse;
	size_t		sz;

	alarm(360);
	if (!(parse = fdopen(fd, "r")))
	{
		warn("fdopen(`%d')", fd);
		return(ERR_CONT);
	}
	while ((line = fgetln(parse, &sz)))
	{
		if (!memmem(line, sz, "<!--#", 5))
		{
			if (print_enabled())
			{
				if (secwrite(line, sz) == EOF)
				{
					alarm(0);
					fclose(parse);
					return(ERR_QUIT);
				}
				*size += sz;
			}
		}
		else
		{
			char	*p, *linecopy = NULL;
			int	ret;

			if (!(p = memchr(line, '\n', sz)))
			{
				/* only if this is the last line */
				MALLOC(linecopy, char, sz + 1);
				memcpy(linecopy, line, sz);
				linecopy[sz] = '\0';
			}
			else
				*p = '\0';

			ret = parsedirectives(linecopy ? linecopy : line, size);
			if (ERR_QUIT == ret)
			{
				alarm(0);
				fclose(parse);
				FREE(linecopy);
				return(ERR_QUIT);
			}
			FREE(linecopy);
		}
	}
	alarm(0);
	fclose(parse);
	return(ERR_NONE);
}

int
sendwithdirectives(int fd, off_t *size)
{
	int	ret;

	ssioutput = 0; ssiarray[0] = 1;
	cnt_readbefore = false;
	numincludes = 0;
	setvarlen = 0;
	switchstr = NULL;
	ret = sendwithdirectives_internal(fd, size);

	while (setvarlen-- > 0)
		FREE(setvars[setvarlen]);
	return ret;
}
