/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2007 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>
#ifdef		HAVE_SYS_PARAM_H
#include	<sys/param.h>
#endif		/* HAVE_SYS_PARAM_H */

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
#ifdef		HAVE_SYS_RESOURCE_H
#include	<sys/resource.h>
#endif		/* HAVE_SYS_RESOURCE_H */

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
static	int	call_counter		(countermode, int, char **, off_t *);
static	int	parse_values		(char *, char **, size_t);
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
static	int	parsedirectives		(char *, off_t *);
static	int	sendwithdirectives_internal (int, off_t *);

#define		MAXINCLUDES	16
#define		CONDKEYWORDS	16
#define		SETVARIABLES	200
#define		SSIARGUMENTS	100
static	int	ssioutput, cnt_readbefore, numincludes;
static	char	ssiarray[CONDKEYWORDS];
static	char	*switchstr;
static	int	setvarlen;
static	char	*setvars[SETVARIABLES];

static	bool
xsc_initdummy(off_t *size)
{
	int		fd;
	countstr	dummy;

	if ((fd = open(calcpath(CNT_DATA), O_WRONLY | O_CREAT,
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
	const	char	*lockfile;

	strlcpy(datafile, calcpath(CNT_DATA), XS_PATH_MAX);
	if ((fd = open(datafile, O_RDONLY,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		*size += secprintf("[Could not open the counter file: %s]\n",
			strerror(errno));
		return false;
	}
	retry = 0;
	while ((fd2 = open(lockfile = calcpath(CNT_LOCK),
		O_WRONLY | O_CREAT | O_EXCL,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0 && retry++ < 10)
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
	int		fd;
	const char	*counterfile;
	char		xscount_version;

	counterfile = calcpath(CNT_DATA);
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
xsc_counter(countermode mode, const char *args, off_t *size)
{
	int			fd = -1, timer, total, x, y, z, comp;
	bool			already = false;
	static	countstr	counter;
	char			*p, filename[sizeof(counter.filename)];

	strlcpy(filename, real_path, sizeof(filename));
	if ((p = strchr(filename, '?')))
		*p = '\0';

	if (cnt_readbefore)
		goto ALREADY;
	cnt_readbefore = 1; timer = 0;
	counter.total = counter.today = counter.month = 0;
	counter.lastseen = (time_t)0;

reopen:
	if ((fd = open(calcpath(CNT_DATA), O_RDWR,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		if (!xsc_initdummy(size))
			return false;
		goto reopen;
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
		goto reopen;
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
		goto reopen;
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
			goto reopen;
		*size += secprintf("[reset stats counter]");
		break;
	}
	return true;
}

static	int
call_counter(countermode mode, int argc, char **argv, off_t *size)
{
	xs_error_t	ret;
	uid_t		savedeuid;
	gid_t		savedegid;
	const	char	*path;

	path = argc ? argv[0] : NULL;
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
parse_values(char *here, char **mapping, size_t maxsize)
{
	char		*p, *e, *word, *args, *end = strstr(here, "-->");
	enum		{ T_INDEX, T_EQUAL, T_VALUE }	expect;
	size_t		len, mapsize;
	bool		guard;

	if (!end)
		return 0;
	*end = '\0';

	len = end + 1 - here;
	args = (char *)malloc(len);
	strlcpy(args, here, len);
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
				mapping[mapsize++] = strdup(word);
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
				mapping[mapsize++] = strdup(word);
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
			mapping[mapsize++] = strdup(word);
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
	free(args);
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
		strlcpy(dateformat, format, MYBUFSIZ);
	(void)size;
	return(ERR_NONE);
}

static	int
dir_date(int argc, char **argv, off_t *size)
{
	int		i;
	char		buffer[MYBUFSIZ];
	char		*format, *zone, *ozone;

	format = dateformat;
	zone = ozone = NULL;
	for (i = 0; i < argc; i += 2)
		if (!strcmp(argv[i], "format"))
			format = argv[i + 1];
		else if (!strcmp(argv[i], "zone"))
			zone = argv[i + 1];

	if (zone)
	{
		if ((ozone = getenv("TZ")))
			ozone = strdup(ozone);
		setenv("TZ", zone, 1);
	}
	*size += strftime(buffer, MYBUFSIZ - 1, format, localtimenow());
	if (ozone)
	{
		setenv("TZ", ozone, 1);
		free(ozone);
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
		*size += secprintf("[Error opening file `%s': %s]\n",
			path, strerror(errno));
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
	char		buffer[MYBUFSIZ];
	struct	stat	statbuf;
	struct	tm	*thetime;

	if (argc)
	{
		path = convertpath(argv[0]);
		if (stat(path, &statbuf))
		{
			*size += secprintf("[Cannot stat file '%s': %s]\n",
				path, strerror(errno));
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

	strftime(buffer, MYBUFSIZ - 1, dateformat, thetime);
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
	char	*querystring, *qs;
	int	oldhead;

	if ((qs = getenv("QUERY_STRING")))
		querystring = strdup(qs);
	else
		querystring = NULL;

	if (!argc)
	{
		*size += secputs("[No parameter for run-cgi]\n");
		return(ERR_CONT);
	}
	oldhead = headers;
	headers = 0;
	do_get(argv[0]);
	headers = oldhead;

	/* used to do something like this - which is way more efficient
	 *
	do_script(here, "", "", NULL, 0);
	 */
	if (querystring)
	{
		setenv("QUERY_STRING", querystring, 1);
		free(querystring);
	}
	if (getenv("ORIG_PATH_INFO"))
	{
		setenv("PATH_INFO", getenv("ORIG_PATH_INFO"), 1);
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
	char **p, *c;

	for (p = environ; (c = *p); ++p)
		*size += secprintf("%s<br>\n", c);
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
		setvars[setvarlen] = strdup(argv[i]);
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
		var = urlencode(value);
		*size += secputs(var);
		free(var);
	}
	else /* enc = "html" */
	{
		var = escape(value);
		*size += secputs(var);
		free(var);
	}
	return(ERR_NONE);
}

static	int
dir_echo_obsolete(int argc, char **argv, off_t *size)
{
	const char	*value = NULL;

	/* argv[0] = ssi name for ssi w/o arguments */
	if (!strcmp(argv[0], "remote-host"))
		value = remotehost;
	else if (!strcmp(argv[0], "agent-long"))
		value = getenv("USER_AGENT");
	else if (!strcmp(argv[0], "agent-short"))
		value = getenv("USER_AGENT_SHORT");
	else if (!strcmp(argv[0], "argument"))
		value = getenv("QUERY_STRING");
	else if (!strcmp(argv[0], "referer"))
		value = getenv("HTTP_REFERER");

	*size += secputs(value ? value : "[none]");
	(void)argc;
	return(ERR_NONE);
}

static	int
dir_if(int argc, char **argv, off_t *size)
{
	int	i, b;
	char	*keyword, *value;

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
		value = remotehost;
	else if (!strcasecmp(keyword, "remote-name"))
		value = getenv("REMOTE_HOST");
	else if (!strcasecmp(keyword, "remote-addr"))
		value = getenv("REMOTE_ADDR");
	else if (!strcasecmp(keyword, "argument"))
		value = getenv("QUERY_STRING");
	else if (!strcasecmp(keyword, "referer"))
		value = getenv("HTTP_REFERER");
	else if (!strcasecmp(keyword, "var"))
	{
		char	*var = NULL;

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
			if (b |= match(value, argv[i]))
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
	switchstr = strdup(argv[0]);
	return(ERR_NONE);
}

static	int
dir_endswitch(int argc, char **argv, off_t *size)
{
	dir_endif(argc, argv, size);
	if (switchstr)
		free(switchstr);
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
	char		params;
	/* padding */
} directivestype;

static	directivestype	directives[] =
{
	{ "count-total",	dir_count_total,	0	},
	{ "count-total-gfx",	dir_count_total_gfx,	1	},
	{ "count-today",	dir_count_today,	0	},
	{ "count-today-gfx",	dir_count_today_gfx,	1	},
	{ "count-month",	dir_count_month,	0	},
	{ "count-month-gfx",	dir_count_month_gfx,	1	},
	{ "count-reset",	dir_count_reset,	0	},
	{ "date",		dir_date,		1	},
	{ "date-format",	dir_date_format,	1	},
	{ "exec",		dir_exec,		1	},
	{ "include",		dir_include_file,	1	},
	{ "include-file",	dir_include_file,	1	},
	{ "last-modified",	dir_last_mod,		1	},
	{ "last-mod",		dir_last_mod,		1	},
	{ "remote-host",	dir_echo_obsolete,	0	},
	{ "run-cgi",		dir_run_cgi,		1	},
	{ "agent-short",	dir_echo_obsolete,	0	},
	{ "agent-long",		dir_echo_obsolete,	0	},
	{ "argument",		dir_echo_obsolete,	0	},
	{ "printenv",		dir_printenv,		0	},
	{ "referer",		dir_echo_obsolete,	0	},
	{ "set",		dir_set,		1	},
	{ "echo",		dir_echo,		1	},
	{ "if",			dir_if,			1	},
	{ "if-not",		dir_if_not,		1	},
	{ "else",		dir_else,		0	},
	{ "endif",		dir_endif,		0	},
	{ "switch",		dir_switch,		1	},
	{ "endswitch",	dir_endswitch,	0	},
	{ "case",		dir_case,		1	},
	{ NULL,			NULL,			0	}
};

static	bool
print_enabled()
{
	bool		output;
	int		count;

	output = false;
	for (count = 0; count <= ssioutput; count++)
		if (!ssiarray[count])
			output = true;
	return(output);
}

static	int
parsedirectives(char *parse, off_t *size)
{
	char		*here, result[MYBUFSIZ], *store;

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
			char		*search;

			if (len < 1 || strcasecmp(directive->name, argv[0]))
				continue;

			if (directive->params)
			{
				/* remove argv[0..1] */
				free(argv[0]);
				for (argc = 0; argc < len - 2; argc++)
					argv[argc] = argv[argc + 2];
			}
			else
				argc = 0;
			if (printable ||
				(directive->func == dir_if) ||
				(directive->func == dir_if_not) ||
				(directive->func == dir_else) ||
				(directive->func == dir_endif) ||
				(directive->func == dir_switch) ||
				(directive->func == dir_endswitch) ||
				(directive->func == dir_case))
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
			if (argv[argc])
				free(argv[argc]);
		if (!directive->name)
		{
			char		*search;

			*size += secputs("[Unknown directive]\n");
			if ((search = strstr(here, "-->")))
				here = search + 3;
		}
		else if (!directive->params)
			free(argv[0]);
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
	char		line[LINEBUFSIZE];
	FILE		*parse;

	alarm(360);
	if (!(parse = fdopen(fd, "r")))
	{
		warn("fdopen(`%d')", fd);
		return(ERR_CONT);
	}
	while (fgets(line, LINEBUFSIZE, parse))
	{
		if (!strstr(line, "<!--#"))
		{
			if (print_enabled())
			{
				if (secputs(line) == EOF)
				{
					alarm(0);
					fclose(parse);
					return(ERR_QUIT);
				}
				*size += strlen(line) + 1;
			}
		}
		else
		{
			if (parsedirectives(line, size) == ERR_QUIT)
			{
				alarm(0);
				fclose(parse);
				return(ERR_QUIT);
			}
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
	cnt_readbefore = numincludes = 0;
	setvarlen = 0;
	switchstr = NULL;
	ret = sendwithdirectives_internal(fd, size);

	while (setvarlen--)
		if (setvars[setvarlen])
			free(setvars[setvarlen]);
	return ret;
}
