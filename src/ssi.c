/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#ifdef		WANT_SSI

#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */
#include	<sys/types.h>
#include	<sys/stat.h>
#ifdef		HAVE_SYS_PARAM_H
#include	<sys/param.h>
#endif		/* HAVE_SYS_PARAM_H */

#ifdef		HAVE_VFORK_H
#include	<vfork.h>
#endif		/* HAVE_VFORK_H */
#include	<stdio.h>
#ifdef		HAVE_TIME_H
#ifdef		TIME_WITH_SYS_TIME
#include	<time.h>
#endif		/* TIME_WITH_SYS_TIME */
#endif		/* HAVE_TIME_H */
#include	<unistd.h>
#ifdef		HAVE_VFORK_H
#include	<vfork.h>
#endif		/* HAVE_VFORK_H */
#include	<errno.h>
#include	<signal.h>
#include	<pwd.h>
#include	<fcntl.h>
#include	<stdlib.h>

#include	"ssi.h"
#include	"httpd.h"
#include	"extra.h"
#include	"local.h"
#include	"path.h"
#include	"ssl.h"
#include	"convert.h"
#include	"xscounter.h"
#include	"methods.h"
#include	"mystring.h"
#include	"htconfig.h"
#include	"setenv.h"

static	int	xsc_initdummy		(void);
static	int	xsc_initcounter		(const char *);
static	int	xsc_counter		(int, const char *);
static	int	call_counter		(int, const char *);
static	int	dir_count_total		(char *, size_t *);
static	int	dir_count_total_gfx	(char *, size_t *);
static	int	dir_count_today		(char *, size_t *);
static	int	dir_count_today_gfx	(char *, size_t *);
static	int	dir_count_month		(char *, size_t *);
static	int	dir_count_month_gfx	(char *, size_t *);
static	int	dir_count_reset		(char *, size_t *);
static	int	dir_date		(char *, size_t *);
static	int	dir_date_format		(char *, size_t *);
static	int	dir_include_file	(char *, size_t *);
static	int	dir_last_mod		(char *, size_t *);
static	int	dir_remote_host		(char *, size_t *);
static	int	dir_run_cgi		(char *, size_t *);
static	int	dir_agent_long		(char *, size_t *);
static	int	dir_agent_short		(char *, size_t *);
static	int	dir_argument	(char *, size_t *);
static	int	dir_referer		(char *, size_t *);
static	int	dir_if			(char *, size_t *);
static	int	dir_if_not		(char *, size_t *);
static	int	dir_else		(char *, size_t *);
static	int	dir_endif		(char *, size_t *);
static	int	dir_switch		(char *, size_t *);
static	int	dir_endswitch	(char *, size_t *);
static	int	dir_case		(char *, size_t *);
static	int	print_enabled		(void);
static	int	parsedirectives		(char *, size_t *);
static	int	sendwithdirectives_internal (int, size_t *);

static	int	ssioutput, cnt_readbefore, numincludes;
static	char	ssiarray[16];
static	int	switchlen;
static	char	*switchstr;

#define		MODE_ALL	0
#define		MODE_GFX_ALL	1
#define		MODE_TODAY	2
#define		MODE_GFX_TODAY	3
#define		MODE_MONTH	4
#define		MODE_GFX_MONTH	5
#define		MODE_RESET	6

static	int
xsc_initdummy()
{
	int		fd;
	countstr	dummy;

	if ((fd = open(calcpath(CNT_DATA), O_WRONLY,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		if ((fd = open(calcpath(CNT_DATA), O_WRONLY | O_CREAT,
			S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
		{
			secprintf("[Failed to create dummies: %s]\n",
				strerror(errno));
			return(1);
		}
	}

	memset(dummy.filename, 1, sizeof(dummy.filename) - 1);
	dummy.filename[sizeof(dummy.filename) - 1] = 0;
	dummy.total = dummy.today = dummy.month = 0;
	if (write(fd, &dummy, sizeof(dummy)) != sizeof(dummy))
	{
		secprintf("[Failed to write dummy file: %s]\n", strerror(errno));
		return(1);
	}

	memset(dummy.filename, 255, sizeof(dummy.filename)-1);
	dummy.filename[sizeof(dummy.filename) - 1] = 0;
	if (write(fd, &dummy, sizeof(dummy)) != sizeof(dummy))
	{
		secprintf("[Failed to write dummy file: %s]\n", strerror(errno));
		return(1);
	}
	close(fd); return(0);
}

static	int
xsc_initcounter(const char *filename)
{
	int		fd, fd2, done;
	countstr	counter, counter2;
	char		datafile[XS_PATH_MAX];
	const	char	*lockfile;

	strlcpy(datafile, calcpath(CNT_DATA), XS_PATH_MAX);
	if ((fd = open(datafile, O_RDONLY,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		secprintf("[Could not open the counter file: %s]\n",
			strerror(errno));
		return(1);
	}
	if ((fd2 = open(lockfile = calcpath(CNT_LOCK),
		O_WRONLY | O_CREAT | O_TRUNC,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		secprintf("[Failed to create temporary file: %s]\n",
			strerror(errno));
		close(fd2); return(1);
	}

	done = 0;
	strlcpy(counter2.filename, filename, sizeof(counter2.filename));
	counter2.total = counter2.today = counter2.month = 0;

	while (read(fd, &counter, sizeof(counter)) == sizeof(counter))
	{
		if ((!done) && (strcmp(counter.filename, filename) > 0))
		{
			if (write(fd2, &counter2, sizeof(counter2)) !=
				sizeof(counter2))
			{
				secprintf("[Failed to write temp file: %s]\n",
					strerror(errno));
				close(fd); close(fd2); remove(lockfile);
				return(1);
			}
			done = 1;
		}
		if (write(fd2, &counter, sizeof(counter)) != sizeof(counter))
		{
			secprintf("[Failed to write temp file: %s]\n",
				strerror(errno));
			close(fd); close(fd2); remove(lockfile); return(1);
		}
	}

	if (!done)
	{
		if (write(fd2, &counter2, sizeof(counter2)) != sizeof(counter2))
			secprintf("[Failed to write temp file: %s]\n",
				strerror(errno));
	}
	close(fd); close(fd2);
	if (rename(lockfile, datafile))
	{
		secprintf("[Could not rename counter file: %s]\n",
			strerror(errno));
		remove(lockfile); return(1);
	}
	remove(lockfile); return(0);
}

static	int
xsc_counter(int mode, const char *args)
{
	char			counterfile[XS_PATH_MAX], host[XS_PATH_MAX];
	const	char		*lockfile;
	struct stat		statbuf;
	int			fd = -1, timer, total, x, y, z, comp, already = 0;
	static	countstr	counter;

	if (cnt_readbefore)
		goto ALREADY;
	cnt_readbefore = 1; timer = 0;
	counter.total = counter.today = counter.month = 0;
	lockfile = calcpath(CNT_LOCK);
	while (!stat(lockfile, &statbuf))
	{
		mysleep(1);
		if ((timer++) == 180)
		{
			secprintf("[Warning! Lock file timed out! Removing it!]\n");
			remove(lockfile); return(1);
		}
	}

	strlcpy(counterfile, calcpath(CNT_DATA), XS_PATH_MAX);

reopen:
	if ((fd = open(counterfile, O_RDWR,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) < 0)
	{
		if (xsc_initdummy())
			return(1);
		goto reopen;
	}

	if ((total = lseek(fd, 0, SEEK_END)) == -1)
	{
		secprintf("[Could not find end of the counter file: %s]\n",
			strerror(errno));
		return(1);
	}

	total /= sizeof(countstr);
	if (total < 2)
	{
		close(fd);
		if (xsc_initdummy())
			return(1);
		goto reopen;
	}

	x = 0; z = total - 1; y = z / 2; comp = 1;
	while ((x < (z-1)) && (comp))
	{
		y = (x + z) / 2;
		if (lseek(fd, y * sizeof(countstr), SEEK_SET) == -1)
		{
			secprintf("[Could not seek in counter file: %s]\n",
				strerror(errno));
			return(1);
		}
		if (read(fd, &counter, sizeof(countstr)) != sizeof(countstr))
		{
			secprintf("[Could not read counter file: %s]\n",
				strerror(errno));
			return(1);
		}
		if ((comp = strcmp(real_path, counter.filename)) < 0)
			z = y;
		else
			x = y;
	}

	if (comp)
	{
		close(fd);
		if (already)
		{
			secprintf("[Failed to create new counter]\n");
			return(1);
		}
		already = 1;
		if (xsc_initcounter(real_path))
			return(1);
		goto reopen;
	}

	counter.total++; counter.today++; counter.month++;
	if (lseek(fd, y * sizeof(countstr), SEEK_SET) == -1)
	{
		secprintf("[Could not seek in counter file: %s]\n",
			strerror(errno));
		close(fd); return(1);
	}
	if (mode == MODE_RESET)
	{
		counter.total = counter.month = counter.today = 0;
		if (write(fd, &counter, sizeof(countstr)) != sizeof(countstr))
		{
			secprintf("[Could not update counter file: %s]\n",
				strerror(errno));
			close(fd); return(1);
		}
	}
	if (write(fd, &counter, sizeof(countstr)) != sizeof(countstr))
	{
		secprintf("[Could not update counter file: %s]\n",
			strerror(errno));
		close(fd); return(1);
	}
ALREADY:
	if (strcmp(cursock->port, "80"))
		snprintf(host, sizeof(host), "http://%s:%s/",
			current->hostname, cursock->port);
	else
		snprintf(host, sizeof(host), "http://%s/", current->hostname);
	switch(mode)
	{
	case MODE_ALL:
		secprintf("%d", counter.total);
		break;
	case MODE_GFX_ALL:
		secprintf("<IMG SRC=\"/%s/gfxcount%s?%d\" ALT=\"%d\">",
			current->execdir,
			args ? args : "", counter.total, counter.total);
		break;
	case MODE_TODAY:
		secprintf("%d", counter.today);
		break;
	case MODE_GFX_TODAY:
		secprintf("<IMG SRC=\"/%s/gfxcount%s?%d\" ALT=\"%d\">",
			current->execdir,
			args ? args : "", counter.today, counter.today);
		break;
	case MODE_MONTH:
		secprintf("%d", counter.month);
		break;
	case MODE_GFX_MONTH:
		secprintf("<IMG SRC=\"/%s/gfxcount%s?%d\" ALT=\"%d\">",
			current->execdir,
			args ? args : "", counter.month, counter.month);
		break;
	case MODE_RESET:
		if (counter.total > 0)
			/* This is quite redundant... Let's think of a better way */
			goto reopen;
		secprintf("[reset stats counter]");
		break;
	}
	close(fd);
	return(0);
}

static	int
call_counter(int mode, const char *args)
{
	int		ret;
	uid_t		savedeuid = -1;
	gid_t		savedegid = -1;
	const	char	*path;
	char		*search;

	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); seteuid(origegid);
	}
	path = search = NULL;
	if (args && (*args == ' '))
	{
		if (!(search = strstr(args, "-->")))
		{
			secprintf("[Incomplete counter directive]\n");
			return(ERR_CONT);
		}
		*search = 0;
		path = args + 1;
	}
	ret = xsc_counter(mode, path) ? ERR_CONT : ERR_NONE;
	if (search)
		*search = '-';
	if (!origeuid)
	{
		setegid(savedegid); seteuid(savedeuid);
	}
	return(ret);
}

static	int
dir_count_total(char *here, size_t *size)
{
	(void)here;
	(void)size;
	return(call_counter(MODE_ALL, NULL));
}

static	int
dir_count_total_gfx(char *here, size_t *size)
{
	(void)size;
	return(call_counter(MODE_GFX_ALL, here));
}

static	int
dir_count_today(char *here, size_t *size)
{
	(void)here;
	(void)size;
	return(call_counter(MODE_TODAY, NULL));
}

static	int
dir_count_today_gfx(char *here, size_t *size)
{
	(void)size;
	return(call_counter(MODE_GFX_TODAY, here));
}

static	int
dir_count_month(char *here, size_t *size)
{
	(void)here;
	(void)size;
	return(call_counter(MODE_MONTH, NULL));
}

static	int
dir_count_month_gfx(char *here, size_t *size)
{
	(void)size;
	return(call_counter(MODE_GFX_MONTH, here));
}

static	int
dir_count_reset(char *here, size_t *size)
{
	(void)size;
	return(call_counter(MODE_RESET, here));
}

static	int
dir_date_format(char *here, size_t *size)
{
	char		*search;

	if (*(here++) != ' ')
	{
		secprintf("[No parameter to date-format]\n");
		return(ERR_CONT);
	}

	if (!(search = strstr(here, "-->")))
	{
		secprintf("[Incomplete directive in date-format]\n");
		return(ERR_CONT);
	}
	*search = 0;
	strlcpy(dateformat, here, MYBUFSIZ);
	*search = '-';
	(void)size;
	return(ERR_NONE);
}

static	int
dir_date(char *here, size_t *size)
{
	char		buffer[MYBUFSIZ];
	time_t		theclock;

	time(&theclock);
	strftime(buffer, MYBUFSIZ - 1, dateformat, localtime(&theclock));
	*size += strlen(buffer);
	(void)here;
	return(secfputs(buffer, stdout) == EOF ? ERR_QUIT : ERR_NONE);
}

static	int
dir_include_file(char *here, size_t *size)
{
	int		fd, ret;
	const	char	*path;
	char		*search;

	if ((numincludes++) > 16)
	{
		secprintf("[Too many include files]\n");
		return(ERR_CONT);
	}
	if (*(here++) != ' ')
	{
		secprintf("[No parameter for include-file]\n");
		return(ERR_CONT);
	}

	if (!(search = strstr(here, "-->")))
	{
		secprintf("[Incomplete directive in include-file]\n");
		return(ERR_CONT);
	}
	if (!strncmp(here, "virtual=\"", 9))
	{
		here += 9;
		search -= 1;
	}
	*search = 0;
	path = convertpath(here);
	fd = open(path, O_RDONLY, 0);
	*search = '-';
	if (fd < 0)
	{
		secprintf("[Error opening file `%s': %s]\n",
			path, strerror(errno));
		return(ERR_CONT);
	}
	*search = '-';
	ret = sendwithdirectives_internal(fd, size);
	numincludes--;
	close(fd);
	if (getenv("ORIG_PATH_INFO"))
		setenv("PATH_INFO", getenv("ORIG_PATH_INFO"), 1);
	if (getenv("ORIG_PATH_TRANSLATED"))
		setenv("PATH_TRANSLATED", getenv("ORIG_PATH_TRANSLATED"), 1);
	return(ret);
}

static	int
dir_last_mod(char *here, size_t *size)
{
	const	char	*path;
	char		*search, buffer[MYBUFSIZ];
	struct	stat	statbuf;
	struct	tm	*thetime;

	if (*here == ' ')
	{
		here++;
		if (!(search = strstr(here, "-->")))
		{
			secprintf("[Incomplete directive in last-mod]\n");
			return(ERR_CONT);
		}
		*search = 0;
		path = convertpath(here);
		*search = '-';
		if (stat(path, &statbuf))
		{
			secprintf("[Cannot stat file '%s': %s]\n",
				path, strerror(errno));
			return(ERR_CONT);
		}
		thetime = localtime(&statbuf.st_mtime);
	} else {
		/* previous SSI's may have broken $modtime */
		if ((path = getenv("ORIG_PATH_TRANSLATED")) &&
				!stat(path, &statbuf))
			thetime = localtime(&statbuf.st_mtime);
		else
			thetime = localtime(&modtime);
	}

	strftime(buffer, MYBUFSIZ - 1, dateformat, thetime);
	*size += strlen(buffer);
	return(secfputs(buffer, stdout) == EOF ? ERR_QUIT : ERR_NONE);
}

static	int
dir_remote_host(char *here, size_t *size)
{
	*size += strlen(remotehost);
	(void)here;
	return(secfputs(remotehost, stdout) == EOF ? ERR_QUIT : ERR_NONE);
}

static	int
dir_run_cgi(char *here, size_t *size)
{
	char	*search, *querystring, *qs, *cgi;
	int		oldhead;

	if ((qs = getenv("QUERY_STRING")))
	{
		if ((querystring = malloc(strlen(qs))))
			strcpy(querystring, qs);
	}
		else
			querystring = NULL;

	if (*here != ' ')
	{
		secprintf("[No parameter for run-cgi]\n");
		return(ERR_CONT);
	}
	if (!(search = strstr(here, "-->")))
	{
		secprintf("[Incomplete directive in run-cgi]\n");
		return(ERR_CONT);
	}
	oldhead = headers;
	headers = 0;
	*search = 0;
	cgi = strdup(here + 1);
	*search = '-';
	do_get(cgi);
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
		setenv("PATH_INFO", getenv("ORIG_PATH_INFO"), 1);
	if (getenv("ORIG_PATH_TRANSLATED"))
		setenv("PATH_TRANSLATED", getenv("ORIG_PATH_TRANSLATED"), 1);
	(void)size;
	return(ERR_NONE);
}

static	int
dir_agent_long(char *here, size_t *size)
{
	if (getenv("USER_AGENT"))
		secprintf("%s", getenv("USER_AGENT"));
	else
		secprintf("Unknown browser");
	(void)here;
	(void)size;
	return(ERR_NONE);
}

static	int
dir_agent_short(char *here, size_t *size)
{
	if (getenv("USER_AGENT_SHORT"))
		secprintf("%s", getenv("USER_AGENT_SHORT"));
	else
		secprintf("Unknown browser");
	(void)here;
	(void)size;
	return(ERR_NONE);
}

static	int
dir_argument(char *here, size_t *size)
{
	if (getenv("QUERY_STRING")) {
		secprintf("%s", getenv("QUERY_STRING"));
	} else {
		secprintf("[Document missing arguments]\n");
		return(ERR_CONT);
	}
	(void)here;
	(void)size;
	return(ERR_NONE);
}

static	int
dir_printenv(char *here, size_t *size)
{
	char **p, *c;

	if (*here != ' ')
	{
		for (p = environ; ((c = *p)); ++p)
			secprintf("<br>%s\n", c);
		return(ERR_NONE);
	}
	if (!(c = strstr(here, "-->")))
	{
		secprintf("[Incomplete directive in printenv]\n");
		return(ERR_CONT);
	}
	*c = '\0';
	secprintf("%s=%s", here+1, getenv(here + 1));
	*c = '-';
	(void)size;
	return ERR_NONE;
}

static	int
dir_referer(char *here, size_t *size)
{
	if (getenv("HTTP_REFERER"))
		secprintf("%s", getenv("HTTP_REFERER"));
	else
		secprintf("No refering URL");
	(void)here;
	(void)size;
	return(ERR_NONE);
}

static	int
dir_if(char *here, size_t *size)
{
	char		*search;

	if (*(here++) != ' ')
	{
		secprintf("[No parameter for if]\n");
		return(ERR_CONT);
	}
	if (!(search = strstr(here, "-->")))
	{
		secprintf("[Incomplete directive in if]\n");
		return(ERR_CONT);
	}
	if (ssioutput == 15)
	{
		secprintf("[Too many nested if statements]\n");
		return(ERR_CONT);
	}
	*search = 0;
	if (!strncasecmp(here, "browser ", 8))
		ssiarray[++ssioutput] = match_list(here + 8,
			getenv("USER_AGENT"));
	else if (!strncasecmp(here, "remote-host ", 11))
		ssiarray[++ssioutput] =
			(match_list(here + 11, getenv("REMOTE_HOST")) ||
			match_list(here + 11, getenv("REMOTE_ADDR")));
	else if (!strncasecmp(here, "remote-name ", 11))
		ssiarray[++ssioutput] = match_list(here + 11,
			getenv("REMOTE_HOST"));
	else if (!strncasecmp(here, "remote-addr ", 11))
		ssiarray[++ssioutput] = match_list(here + 11,
			getenv("REMOTE_ADDR"));
	else if (!strncasecmp(here, "argument ", 9))
		ssiarray[++ssioutput] = match_list(here + 9,
			getenv("QUERY_STRING"));
	else if (!strncasecmp(here, "referer ", 8))
		ssiarray[++ssioutput] = match_list(here + 8,
			getenv("HTTP_REFERER"));
	else
	{
		secprintf("[Unknown if subtype]\n");
		*search = '-'; return(ERR_CONT);
	}
	*search = '-';
	(void)size;
	return(ERR_NONE);
}

static	int
dir_if_not(char *here, size_t *size)
{
	if (dir_if(here, size) != ERR_NONE)
		return(ERR_CONT);
	ssiarray[ssioutput] = !ssiarray[ssioutput];
	return(ERR_NONE);
}

static	int
dir_else(char *here, size_t *size)
{
	ssiarray[ssioutput] = !ssiarray[ssioutput];
	(void)here;
	(void)size;
	return(ERR_NONE);
}

static	int
dir_endif(char *here, size_t *size)
{
	if (!ssioutput)
	{
		secprintf("[No if's to endif]\n");
		return(ERR_CONT);
	}
	ssioutput--;
	(void)here;
	(void)size;
	return(ERR_NONE);
}

static	int
dir_switch(char *here, size_t *size)
{
	if (*(here++) != ' ')
	{
		secprintf("[No parameter for switch]\n");
		return(ERR_CONT);
	}
	if (!strstr(here, "-->"))
	{
		secprintf("[Incomplete directive in switch]\n");
		return(ERR_CONT);
	}
	ssiarray[++ssioutput] = 0;

	switchlen = strlen(here);
	switchstr = realloc(switchstr, strlen(here));
	switchstr[0] = ' ';
	switchstr[1] = '\0';
	strcat(switchstr, here);
	switchstr[switchlen-3] = '\0';
	(void)size;
	return(ERR_NONE);
}

static	int
dir_endswitch(char *here, size_t *size)
{
	dir_endif(here, size);
	return(ERR_NONE);
}

static	int
dir_case(char *here, size_t *size)
{
	char *casestr = malloc(256);

	strlcpy(casestr, switchstr, switchlen);
	strlcat(casestr, here, 256);

	dir_endif(here, size);
	if (dir_if(casestr, size) != ERR_NONE)
		return(ERR_CONT);

	return(ERR_NONE);
}

typedef	struct
{
	const	char	*name;
	int		(*func) (char *, size_t *);
	char		params;
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
	{ "date",		dir_date,		0	},
	{ "date-format",	dir_date_format,	1	},
	{ "include",		dir_include_file,	1	},
	{ "include-file",	dir_include_file,	1	},
	{ "last-modified",	dir_last_mod,		1	},
	{ "last-mod",		dir_last_mod,		1	},
	{ "remote-host",	dir_remote_host,	0	},
	{ "run-cgi",		dir_run_cgi,		1	},
	{ "agent-short",	dir_agent_short,	0	},
	{ "agent-long",		dir_agent_long,		0	},
	{ "argument",		dir_argument,		0	},
	{ "printenv",		dir_printenv,		1	},
	{ "referer",		dir_referer,		0	},
	{ "if",			dir_if,			1	},
	{ "if-not",		dir_if_not,		1	},
	{ "else",		dir_else,		0	},
	{ "endif",		dir_endif,		0	},
	{ "switch",		dir_switch,		1	},
	{ "endswitch",	dir_endswitch,	0	},
	{ "case",		dir_case,		1	},
	{ NULL,			NULL,			0	}
};

static	int
print_enabled()
{
	int		count, output;

	output = 1;
	for (count = 0; count <= ssioutput; count++)
		if (!ssiarray[count])
			output = 0;
	return(output);
}

static	int
parsedirectives(char *parse, size_t *size)
{
	char		*here, *search, result[MYBUFSIZ], *store;
	int		len, printable;
	directivestype	*directive;

	store = result; here = parse;
	while (*here)
	{
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
				if (secfwrite(result, store - result, 1, stdout) != 1)
					return(ERR_QUIT);
				*size += (store - result);
			}
			store = result;
		}
		here += 5;
		for (directive = directives; directive->name; directive++)
		{
			len = strlen(directive->name);
			if (strncasecmp(directive->name, here, len) ||
					(strncmp(here+len, "-->", 3) && here[len] != ' '))
				continue;

			if (!directive->params &&
				strncmp(here+len, "-->", 3))
			{
				secprintf("[Garbage after `%s']",
					directive->name);
			}
			else if (printable ||
				(directive->func == dir_if) ||
				(directive->func == dir_if_not) ||
				(directive->func == dir_else) ||
				(directive->func == dir_endif) ||
				(directive->func == dir_switch) ||
				(directive->func == dir_endswitch) ||
				(directive->func == dir_case))
			{
				switch(directive->func(here + len, size))
				{
				case ERR_QUIT:
					return(ERR_QUIT);
				case ERR_CONT:
					secprintf("[Error parsing directive]\n");
					break;
				}
			}
			if ((search = strstr(here, "-->")))
				here = search + 3;
			break;
		}
		if (!directive->name)
		{
			secprintf("[Unknown directive]\n");
			if ((search = strstr(here, "-->")))
				here = search + 3;
		}
	}

	if (store != result)
	{
		if (print_enabled())
		{
			if (secfwrite(result, store - result, 1, stdout) != 1)
				return(ERR_QUIT);
			*size += (store - result);
		}
	}
	return(ERR_NONE);
}

static	int
sendwithdirectives_internal(int fd, size_t *size)
{
	char		input[MYBUFSIZ];
	FILE		*parse;

	alarm(360);
	if (!(parse = fdopen(fd, "r")))
	{
		fprintf(stderr, "[%s] httpd: Could not fdopen (%d): %s\n",
			currenttime, fd, strerror(errno));
		return(ERR_CONT);
	}
	while (fgets(input, MYBUFSIZ, parse))
	{
		if (!strstr(input, "<!--#"))
		{
			if (print_enabled())
			{
				if (secfputs(input, stdout) == EOF)
				{
					alarm(0); fclose(parse);
					return(ERR_QUIT);
				}
				*size += strlen(input);
			}
		} else
		{
			if (parsedirectives(input, size) == ERR_QUIT)
			{
				alarm(0); fclose(parse);
				return(ERR_QUIT);
			}
		}
	}
	alarm(0);
	fclose(parse);
	return(ERR_NONE);
}

int
sendwithdirectives(int fd, size_t *size)
{
	ssioutput = 0; ssiarray[0] = 1; cnt_readbefore = numincludes = 0;
	return(sendwithdirectives_internal(fd, size));
}

#endif		/* WANT_SSI */
