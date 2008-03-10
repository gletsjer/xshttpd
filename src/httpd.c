/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<inttypes.h>
#ifdef		HAVE_SYS_RESOURCE_H
#include	<sys/resource.h>
#endif		/* HAVE_SYS_RESOURCE_H */
#ifdef		HAVE_SYS_MMAN_H
#include	<sys/mman.h>
#endif		/* HAVE_SYS_MMAN_H */
#include	<sys/socket.h>
#include	<sys/wait.h>
#include	<sys/signal.h>
#include	<sys/stat.h>
#include	<sys/utsname.h>
#include	<sys/file.h>
#ifdef		HAVE_SYS_SELECT_H
#include	<sys/select.h>
#endif		/* HAVE_SYS_SELECT_H */
#ifdef		HAVE_SYS_PARAM_H
#include	<sys/param.h>
#endif		/* HAVE_SYS_PARAM_H */
#ifdef		HAVE_SYS_SYSLIMITS_H
#include	<sys/syslimits.h>
#endif		/* HAVE_SYS_SYSLIMITS_H */

#include	<netinet/in.h>
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>

#include	<arpa/inet.h>

#include	<fcntl.h>
#include	<stdio.h>
#include	<errno.h>
#include	<netdb.h>
#ifndef		NI_MAXSERV
#define		NI_MAXSERV	32
#define		NI_MAXHOST	1025
#endif		/* NI_MAXSERV */
#include	<time.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<string.h>
#include	<signal.h>
#include	<pwd.h>
#include	<grp.h>
#include	<unistd.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<ctype.h>
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */
#ifdef		HAVE_CURL
#include	<curl/curl.h>
#endif		/* HAVE_CURL */

#include	"htconfig.h"
#include	"httpd.h"
#include	"cloader.h"
#include	"decode.h"
#include	"methods.h"
#include	"extra.h"
#include	"cgi.h"
#include	"ssi.h"
#include	"ssl.h"
#include	"path.h"
#include	"convert.h"
#include	"authenticate.h"
#include	"ldap.h"
#include	"malloc.h"
#include	"fcgi.h"

static char copyright[] = "Copyright 1995-2008 Sven Berkvens, Johan van Selst";

/* Global variables */

int		headers, rstatus;
bool		headonly, postonly, postread, chunked, persistent, trailers;
static	int	sd, reqs, reqsc;
static	bool	mainhttpd = true, in_progress = false;
gid_t		origegid;
uid_t		origeuid;
char		remotehost[NI_MAXHOST], remoteaddr[NI_MAXHOST],
		currenttime[80], httpver[16], dateformat[MYBUFSIZ],
		real_path[XS_PATH_MAX], currentdir[XS_PATH_MAX],
		orig_filename[XS_PATH_MAX];
static	int	pidlock = -1;
static	char	browser[MYBUFSIZ], referer[MYBUFSIZ],
		message503[MYBUFSIZ], orig[MYBUFSIZ],
		*startparams;
#define CLEANENV do { \
	MALLOC(environ, char *, 1);\
	*environ = NULL; } while (0)

/* Prototypes */

static	void	filedescrs		(void);
static	void	detach			(void);
static	void	child_handler		(int);
static	void	term_handler		(int)	NORETURN;
static	void	write_pidfile		(void);
static	void	open_logs		(int);
static	void	core_handler		(int)	NORETURN;
static	void	set_signals		(void);

static	void	process_request		(void);

static	void	setup_environment	(void);
static	void	standalone_main		(void)	NORETURN;
static	void	standalone_socket	(int)	NORETURN;

void
stdheaders(bool lastmod, bool texthtml, bool endline)
{
	setcurrenttime();
	secprintf("Date: %s\r\nServer: %s\r\n", currenttime, SERVER_IDENT);
	if (lastmod)
		secprintf("Last-modified: %s\r\nExpires: %s\r\n",
			currenttime, currenttime);
	if (texthtml)
		secputs("Content-type: text/html\r\n");
	if (endline)
		secputs("\r\n");
}

static	void
filedescrs()
{
	close(0);
	if (open(BITBUCKETNAME, O_RDONLY, 0) != 0)
		err(1, "Cannot open fd 0 (%s)", BITBUCKETNAME);
	if (dup2(0, 1) != 1)
		err(1, "Cannot dup2() fd 1");
}

static	void
detach()
{
	pid_t		x;

	if (chdir("/"))
		err(1, "chdir(`/')");
	if ((x = fork()) > 0)
		exit(0);
	else if (x == -1)
		err(1, "fork()");
#ifdef		HAVE_SETSID
	if (setsid() == -1)
		err(1, "setsid() failed");
#else		/* Not HAVE_SETSID */
	if (setpgrp(getpid(), 0) == -1)
		err(1, "setpgrp() failed");
#endif		/* HAVE_SETSID */
}

void
setcurrenttime()
{
	time_t		thetime;

	time(&thetime);
	strftime(currenttime, sizeof(currenttime),
		"%a, %d %b %Y %H:%M:%S GMT", gmtime(&thetime));
}

static	void
child_handler(int sig)
{
	int		status;

	while (waitpid(-1, &status, WNOHANG) > 0)
		/* NOTHING */;
	set_signals();
	(void)sig;
	(void)status;
}

static	void
term_handler(int sig)
{
	if (!mainhttpd)
		exit(0);

	setcurrenttime();
	fprintf(stderr, "[%s] Received signal %d, shutting down...\n",
		currenttime, sig);
	fflush(stderr);
	close(sd);
	killfcgi();
	mainhttpd = false;
	killpg(0, SIGTERM);

	(void)sig;
	exit(0);
	/* NOTREACHED */
}

static	void
write_pidfile(void)
{
	FILE		*pidlog;

	if (!mainhttpd)
		return;
	if (pidlock >= 0)
		flock(pidlock, LOCK_UN);

#ifdef		O_EXLOCK
	pidlock = open(calcpath(config.pidfile),
		O_WRONLY | O_TRUNC | O_CREAT | O_NONBLOCK | O_EXLOCK);
	if ((pidlock < 0) && (EOPNOTSUPP == errno))
#endif		/* O_EXLOCK */
		pidlock = open(calcpath(config.pidfile),
			O_WRONLY | O_TRUNC | O_CREAT);

	if ((pidlock < 0) || !(pidlog = fdopen(pidlock, "w")))
		errx(1, "Cannot open pidfile `%s'", config.pidfile);

	fprintf(pidlog, "%" PRIpid "\n%s\n", getpid(), startparams);
	fflush(pidlog);
}

static	void
open_logs(int sig)
{
	uid_t		savedeuid;
	gid_t		savedegid;

	if (sig)
	{
		remove_config(); load_config();
	}
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
	if (mainhttpd)
	{
		/* the master reloads, the children die */
		signal(SIGHUP, SIG_IGN);
		killpg(0, SIGHUP);
	}

	for (current = config.system; current; current = current->next)
	{
		/* access */
		if (current->logaccess)
		{
			if ('|' != current->logaccess[0])
			{
				if (current->openaccess)
					fclose(current->openaccess);
				if (!(current->openaccess =
					fopen(calcpath(current->logaccess), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logaccess);
				}
			}
			else /* use_pipe */
			{
				if (current->openaccess)
					pclose(current->openaccess);
				if (!(current->openaccess =
					popen(current->logaccess + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logaccess);
				}
			}
			setvbuf(current->openaccess, NULL, _IOLBF, 0);
		}

		/* XXX: evil code duplication */
		if (current->logstyle == log_traditional && current->logreferer)
		{
			/* referer */
			if ('|' != current->logreferer[0])
			{
				if (current->openreferer)
					fclose(current->openreferer);
				if (!(current->openreferer =
					fopen(calcpath(current->logreferer), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logreferer);
				}
			}
			else /* use pipe */
			{
				if (current->openreferer)
					pclose(current->openreferer);
				if (!(current->openreferer =
					popen(current->logreferer + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logreferer);
				}
			}
			setvbuf(current->openreferer, NULL, _IOLBF, 0);
		}

		/* XXX: evil code duplication */
		if (current->logerror)
		{
			/* error */
			if ('|' != current->logerror[0])
			{
				if (current->openerror)
					fclose(current->openerror);
				if (!(current->openerror =
					fopen(calcpath(current->logerror), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logerror);
				}
			}
			else /* use pipe */
			{
				if (current->openerror)
					pclose(current->openerror);
				if (!(current->openerror =
					popen(current->logerror + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logerror);
				}
			}
			setvbuf(current->openerror, NULL, _IOLBF, 0);
		}

		/* XXX: evil code duplication */
		if (current->logscript)
		{
			/* error */
			if ('|' != current->logscript[0])
			{
				if (current->openscript)
					fclose(current->openscript);
				if (!(current->openscript =
					fopen(calcpath(current->logscript), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logscript);
				}
			}
			else /* use pipe */
			{
				if (current->openscript)
					pclose(current->openscript);
				if (!(current->openscript =
					popen(current->logscript + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logscript);
				}
			}
			setvbuf(current->openscript, NULL, _IOLBF, 0);
		}
	}

	fflush(stderr);
	close(2);

	/* local block */
	{
		int		tempfile;

		tempfile = fileno(config.system->openerror);
		if (tempfile != 2)
		{
			if (dup2(tempfile, 2) == -1)
				err(1, "dup2() failed");
		}
		else
			config.system->openerror = stderr;
	}

	if (mainhttpd)
	{
		setcurrenttime();
		fprintf(stderr, "[%s] Successful restart\n", currenttime);
	}
	loadfiletypes(NULL, NULL);
	loadcompresstypes();
	loadscripttypes(NULL, NULL);
#ifdef		HAVE_PERL
	loadperl();
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
	loadpython();
#endif		/* HAVE_PYTHON */
#ifdef		HAVE_CURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif		/* HAVE_CURL */
	set_signals();
	if (!origeuid)
	{
		if (seteuid(savedeuid) == -1)
			err(1, "seteuid()");
		if (setegid(savedegid) == -1)
			err(1, "setegid()");
	}
}

void
alarm_handler(int sig)
{
	alarm(0);
	if (!in_progress)
	{
		fflush(stdout); fflush(stdin); fflush(stderr);
		endssl();
		close(0);
		close(1);
		persistent = false;
		return;
	}
	(void)sig;
	exit(1);
}

static	void
core_handler(int sig)
{
	const	char	*env;

	alarm(0); setcurrenttime();
	env = getenv("QUERY_STRING");
	errx(1, "[%s] httpd(pid % " PRIpid "): FATAL SIGNAL %d [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']",
		currenttime, getpid(), sig,
		remotehost[0] ? remotehost : "(none)",
		orig[0] ? orig : "(none)", env ? env : "(none)",
		current ? current->hostname : config.system->hostname,
		referer[0] ? referer : "(none)");
}

static	void
set_signals()
{
	struct	sigaction	action;

#ifdef		HAVE_SIGEMPTYSET
	sigemptyset(&action.sa_mask);
#else		/* Not HAVE_SIGEMPTYSET */
	action.sa_mask = 0;
#endif		/* HAVE_SIGEMPTYSET */

	action.sa_handler = open_logs;
#ifdef		SA_RESTART
	action.sa_flags = SA_RESTART;
#else		/* Not SA_RESTART */
	action.sa_flags = 0;
#endif		/* SA_RESTART */
	sigaction(SIGHUP, &action, NULL);

	action.sa_handler = child_handler;
	action.sa_flags = 0;
	sigaction(SIGCHLD, &action, NULL);

	action.sa_handler = alarm_handler;
	action.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);

	action.sa_handler = term_handler;
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);

	action.sa_handler = term_handler;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);

	if (!config.usecoredump)
	{
#ifdef		SIGBUS
		action.sa_handler = core_handler;
		action.sa_flags = 0;
		sigaction(SIGBUS, &action, NULL);
#endif		/* SIGBUS */

#ifdef		SIGSEGV
		action.sa_handler = core_handler;
		action.sa_flags = 0;
		sigaction(SIGSEGV, &action, NULL);
#endif		/* SIGSEGV */
	}
}

void
xserror(int code, const char *format, ...)
{
	const	char	*env;
	char		*errmsg = NULL;
	va_list		ap;
	char		*message;

	alarm(180);
	va_start(ap, format);
	vasprintf(&message, format, ap);
	va_end(ap);

	/* log error */
	setcurrenttime();
	env = getenv("QUERY_STRING");
	fprintf((current && current->openerror) ? current->openerror : stderr,
		"[%s] httpd(pid %" PRIpid "): %03d %s [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']\n",
		currenttime, getpid(), code, message,
		remotehost[0] ? remotehost : "(none)",
		orig[0] ? orig : "(none)", env ? env : "(none)",
		current ? current->hostname : config.system->hostname,
		referer[0] ? referer : "(none)");
	fflush(stderr);

	if (599 == code)
		/* connection closed: don't send error */
		return;

	/* display error */
	if (!headonly)
	{
		asprintf(&errmsg,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
			"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n\n"
			"<head><title>%03d %s</title></head>\n"
			"<body><h1>%03d %s</h1></body></html>\n",
			code, message,
			code, message);
	}
	if (headers)
	{
		secprintf("%s %03d %s\r\n", httpver, code, message);
		secprintf("Content-length: %zu\r\n",
			errmsg ? strlen(errmsg) : 0);
		if ((env = getenv("HTTP_ALLOW")))
			secprintf("Allow: %s\r\n", env);
		stdheaders(true, true, true);
	}
	if (!headonly)
	{
		secputs(errmsg);
		free(errmsg);
	}
}

void
redirect(const char *redir, bool permanent, bool pass_env)
{
	const	char	*env = NULL;
	char		*errmsg = NULL;

	if (pass_env)
		env = getenv("QUERY_STRING");
	if (!headonly)
	{
		asprintf(&errmsg,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
			"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
			"<head><title>Document has moved</title></head>\n"
			"<body><h1>Document has moved</h1>\n"
			"<p>This document has %s moved to "
			"<a href=\"%s%s%s\">%s</a>.</p></body></html>\n",
			permanent ?  "permanently" : "",
			redir, env ? "?" : "", env ? env : "", redir);
	}
	if (headers)
	{
		if (env)
			secprintf("%s %s moved\r\nLocation: %s?%s\r\n", httpver,
				permanent ? "301 Permanently" : "302 Temporarily", redir, env);
		else
			secprintf("%s %s moved\r\nLocation: %s\r\n", httpver,
				permanent ? "301 Permanently" : "302 Temporarily", redir);
		secprintf("Content-length: %zu\n", errmsg ? strlen(errmsg) : 0);
		stdheaders(true, true, true);
	}
	rstatus = permanent ? 301 : 302;
	if (!headonly)
	{
		secputs(errmsg);
		free(errmsg);
	}
	fflush(stdout);
}

void
server_error(int code, const char *readable, const char *cgi)
{
	char		cgipath[XS_PATH_MAX],
			errmsg[LINEBUFSIZE];
	const char	filename[] = "/error";
	const char	*env;

	if (!current)
		current = config.system;
	if (headonly || getenv("ERROR_CODE"))
	{
		xserror(code, "%s", readable);
		return;
	}
	setenv("ERROR_CODE", cgi, 1);
	snprintf(errmsg, LINEBUFSIZE, "%03d %s", code, readable);
	setenv("ERROR_READABLE", errmsg, 1);
	setenv("ERROR_URL", orig, 1);
	setenv("ERROR_URL_EXPANDED", convertpath(orig), 1);
	setenv("ERROR_URL_ESCAPED", *orig ? escape(orig) : "", 1);
	env = getenv("QUERY_STRING");
	/* Look for user-defined error script */
	if (current == config.users)
	{
		const char * const username = getenv("USER");

		if (username)
		{
			snprintf(cgipath, XS_PATH_MAX, "/~%s/%s%s",
				username, current->execdir, filename);
			strlcpy(cgipath, convertpath(cgipath), XS_PATH_MAX);
		}
	}
	else	/* Look for virtual host error script */
	{
		snprintf(cgipath, XS_PATH_MAX, "%s%s",
			calcpath(current->phexecdir), filename);
	}

	/* local block */
	{
		struct	stat		statbuf;

		if (stat(cgipath, &statbuf))
		{
			/* Last resort: try system error script */
			snprintf(cgipath, XS_PATH_MAX, "%s%s",
				calcpath(config.system->phexecdir), filename);
			if (stat(cgipath, &statbuf))
			{
				xserror(code, "%s", readable);
				return;
			}
		}
	}
	{
		char	*temp = strrchr(cgipath, '/');
		if (temp)
			*temp = '\0';
	}
	setcurrenttime();
	fprintf((current && current->openerror) ? current->openerror : stderr,
		"[%s] httpd(pid %" PRIpid "): %03d %s [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']\n",
		currenttime, getpid(), code, readable,
		remotehost[0] ? remotehost : "(none)",
		orig[0] ? orig : "(none)", env ? env : "(none)",
		current ? current->hostname : config.system->hostname,
		referer[0] ? referer : "(none)");
	do_script(orig, cgipath, filename, NULL);
}

void
logrequest(const char *request, off_t size)
{
	char		buffer[90], *dynrequest, *dynagent, *p;
	FILE		*alog;

	strftime(buffer, 80, "%d/%b/%Y:%H:%M:%S +0000", localtimenow());

	if (!current->openaccess)
		if (!config.system->openaccess)
		{
			warnx("Logfile disappeared???");
			return;
		}
		else
			alog = config.system->openaccess;
	else
		alog = current->openaccess;

	dynrequest = dynagent = NULL;
	if (request && (dynrequest = strdup(request)))
		for (p = dynrequest; *p; p++)
			if ('\"' == *p)
				*p = '\'';
	if (getenv("USER_AGENT") && (dynagent = strdup(getenv("USER_AGENT"))))
		for (p = dynagent; *p; p++)
			if ('\"' == *p)
				*p = '\'';

	switch (current->logstyle)
	{
	case log_traditional:
		{
		FILE	*rlog = current->openreferer
			? current->openreferer
			: config.system->openreferer;
		fprintf(alog, "%s - - [%s] \"%s %s %s\" %03d %" PRIoff "\n",
			remotehost,
			buffer,
			getenv("REQUEST_METHOD"), dynrequest, httpver,
			rstatus,
			size > 0 ? size : 0);
		if (rlog &&
			(!current->thisdomain || !strcasestr(referer, current->thisdomain)))
			fprintf(rlog, "%s -> %s\n", referer, request);
		}
		break;
	case log_virtual:
		/* this is combined format + virtual hostname */
		fprintf(alog, "%s %s - - [%s] \"%s %s %s\" %03d %" PRIoff
				" \"%s\" \"%s\"\n",
			current ? current->hostname : config.system->hostname,
			remotehost,
			buffer,
			getenv("REQUEST_METHOD"), dynrequest, httpver,
			rstatus,
			size > 0 ? size : 0,
			referer,
			dynagent);
		break;
	case log_combined:
		fprintf(alog, "%s - - [%s] \"%s %s %s\" %03d %" PRIoff
				" \"%s\" \"%s\"\n",
			remotehost,
			buffer,
			getenv("REQUEST_METHOD"), dynrequest, httpver,
			rstatus,
			size > 0 ? size : 0,
			referer,
			dynagent);
		break;
	case log_none:
		/* DO NOTHING */
		break;
	}

	free(dynrequest);
	free(dynagent);
}

static	void
process_request()
{
	char		line[LINEBUFSIZE],
			http_host[NI_MAXHOST], http_host_long[NI_MAXHOST],
			*params, *url, *ver;

	headers = 11;
	strlcpy(httpver, "HTTP/1.1", sizeof(httpver));
	strlcpy(dateformat, "%a %b %e %H:%M:%S %Y", MYBUFSIZ);

	orig[0] = referer[0] = line[0] =
		real_path[0] = browser[0] = authentication[0] = '\0';
	headonly = postonly = false;
	current = NULL;
	setup_environment();

	http_host[0] = '\0';

	rstatus = 200;
	errno = 0;
	chunked = false;
	persistent = false;
	trailers = false;
#ifdef		HAVE_LIBMD
	md5context = NULL;
#endif		/* HAVE_LIBMD */

	initreadmode(false);
	switch (readline(0, line, sizeof(line)))
	{
	case ERR_NONE:
		break;
	case ERR_LINE:
		xserror(414, "Request-URI Too Long");
		return;
	case ERR_CLOSE:
		/* connection close: terminate quietly */
		return;
	case ERR_QUIT:
	default:
		xserror(400, "Unable to read begin of request line");
		return;
	}
	in_progress = true;

	url = line;
	while (*url && (*url > ' '))
		url++;
	*(url++) = 0;
	while (*url && *url <= ' ')
		url++;
	ver = url;
	while (*ver && (*ver > ' '))
		ver++;
	*(ver++) = 0;
	while (*ver && *ver <= ' ')
		ver++;

	for (char *p = ver; *p; p++)
		if (*p <= ' ')
			*p-- = 0;

	alarm(180);
	if (!strncasecmp(ver, "HTTP/", 5))
	{
		if (!strncmp(ver + 5, "1.0", 3))
		{
			strlcpy(httpver, "HTTP/1.0", sizeof(httpver));
			headers = 10;
		}
		else
		{
			strlcpy(httpver, "HTTP/1.1", sizeof(httpver));
			headers = 11;
			persistent = true;
		}
		setenv("SERVER_PROTOCOL", httpver, 1);
		if (!strcasecmp(line, "TRACE"))
		{
			params = url;
			goto METHOD;
		}

		struct maplist	http_headers;
		if (readheaders(0, &http_headers) < 0)
		{
			xserror(400, "Unable to read request line");
			return;
		}
		for (size_t sz = 0; sz < http_headers.size; sz++)
		{
			const char	*idx = http_headers.elements[sz].index;
			const char	*val = http_headers.elements[sz].value;

			if (!strcasecmp("Content-length", idx))
				setenv("CONTENT_LENGTH", val, 1);
			else if (!strcasecmp("Content-type", idx))
				setenv("CONTENT_TYPE", val, 1);
			else if (!strcasecmp("User-agent", idx))
			{
				strlcpy(browser, val, MYBUFSIZ);
				setenv("USER_AGENT", browser, 1);
				setenv("HTTP_USER_AGENT", browser, 1);
				(void) strtok(browser, "/");
				for (char *p = browser; *p; p++)
					if (isupper(*p))
						*p = tolower(*p);
				if (islower(*browser))
					*browser = toupper(*browser);
				setenv("USER_AGENT_SHORT", browser, 1);
			}
			else if (!strcasecmp("Referer", idx))
			{
				strlcpy(referer, val, MYBUFSIZ);
				while (referer[0] &&
					referer[strlen(referer) - 1] <= ' ')
					referer[strlen(referer) - 1] = 0;
				setenv("HTTP_REFERER", referer, 1);
			}
			else if (!strcasecmp("Authorization", idx))
			{
				strlcpy(authentication, val, MYBUFSIZ);
				setenv("HTTP_AUTHORIZATION", val, 1);
			}
			else if (!strcasecmp("Connection", idx))
			{
				if (strcasestr(val, "close"))
					persistent = false;
				setenv("HTTP_CONNECTION", val, 1);
			}
			else if (!strcasecmp("TE", idx))
			{
				if (strcasestr(val, "trailers"))
					trailers = true;
				setenv("HTTP_TE", val, 1);
			}
			else if (!strcasecmp("X-Forwarded-For", idx))
				/* People should use the HTTP/1.1 variant */
				setenv("HTTP_CLIENT_IP", val, 1);
			else
			{
				/* Blindly copy any other header value */
				char	*ptr;
				char	*name;

				asprintf(&name, "HTTP_%s", idx);
				for (ptr = name + 5; *ptr; ptr++)
					if (*ptr >= 'A' && *ptr <= 'Z')
						/* DO NOTHING */;
					else if (*ptr >= 'a' && *ptr <= 'z')
						*ptr -= 'a' - 'A';
					else if ('-' == *ptr)
						*ptr = '_';
					else
						break;
				if (!*ptr)
					setenv(name, val, 1);
				free(name);
			}
		}
		freeheaders(&http_headers);
	}
	else if (!strncasecmp(ver, "HTCPCP/", 7))
	{
		headers = 10;
		strlcpy(httpver, "HTCPCP/1.0", sizeof(httpver));
		xserror(418, "Duh... I'm a webserver Jim, not a coffeepot!");
		return;
	}
	else
	{
		headers = 0;
		strlcpy(httpver, "HTTP/0.9", sizeof(httpver));
		setenv("SERVER_PROTOCOL", httpver, 1);
	}

	if (!getenv("CONTENT_LENGTH"))
	{
		const char	*te = getenv("HTTP_TRANSFER_ENCODING");

		if (headers >= 11 &&
			(!strcasecmp("POST", line) || !strcasecmp("PUT", line)) &&
			(!te || strcasecmp(te, "chunked")))
		{
			xserror(411, "Length Required");
			return;
		}
		setenv("CONTENT_LENGTH", "0", 1);
	}
	if (!browser[0])
	{
		setenv("USER_AGENT", "UNKNOWN", 1);
		setenv("HTTP_USER_AGENT", "UNKNOWN", 1);
		setenv("USER_AGENT_SHORT", "UNKNOWN", 1);
	}

	alarm(0);
	params = url;
	if (!decode(params))
	{
		xserror(500, "Cannot process request");
		return;
	}

	strlcpy(orig, params, MYBUFSIZ);

	if (strlen(orig) < NI_MAXHOST)
	{
		char	ch;

		if (sscanf(params, "http://%[^/]%c", http_host, &ch) == 2 &&
			ch == '/')
		{
			/* absoluteURI's are supported by HTTP/1.1,
			 * this syntax is preferred over Host-headers(!)
			 */
			setenv("HTTP_HOST", http_host, 1);
			params += strlen(http_host) + 7;
			strlcpy(orig, params, MYBUFSIZ);
		}
	}
	else if (params[0] != '/' && strcasecmp("OPTIONS", line))
	{
		xserror(400, "Relative URL's are not supported");
		return;
	}
	/* SERVER_NAME may be overriden soon */
	setenv("SERVER_NAME", config.system->hostname, 1);
	if (getenv("HTTP_HOST"))
	{
		char	*temp;

		strlcpy(http_host, getenv("HTTP_HOST"), NI_MAXHOST);
		for (temp = http_host; *temp; temp++)
			if ((*temp < 'a' || *temp > 'z') &&
				(*temp < 'A' || *temp > 'Z') &&
				(*temp < '0' || *temp > '9') &&
				*temp != '-' && *temp != '.' &&
				*temp != ':' &&
				*temp != '[' && *temp != ']')
			{
				xserror(400, "Invalid Host Header");
				return;
			}
		if ((temp = strchr(http_host, ':')))
			*temp = '\0';
		temp = http_host + strlen(http_host);
		while (temp > http_host && *(--temp) == '.')
			*temp = '\0';
		if (strcmp(cursock->port, cursock->usessl ? "https" : "http") &&
			strcmp(cursock->port, cursock->usessl ? "443" : "80"))
		{
			if (strlen(http_host) >= NI_MAXHOST - 6)
			{
				xserror(400, "Invalid Host Header");
				return;
			}
			strlcat(http_host, ":", NI_MAXHOST);
			strlcat(http_host, cursock->port, NI_MAXHOST);
		}
		unsetenv("HTTP_HOST");
		/* Ignore unqualified names - it could be a subdirectory! */
		if ((strlen(http_host) > 3) && strchr(http_host, '.'))
		{
			setenv("HTTP_HOST", http_host, 1);
			unsetenv("SERVER_NAME");
			setenv("SERVER_NAME", http_host, 1);
		}
	}
	else if (headers >= 11)
	{
		xserror(400, "Missing Host Header");
		return;
	}

	/* local block */
	{
		char	*temp = strchr(http_host, ':');

		if (temp)
		{
			strlcpy(http_host_long, http_host, NI_MAXHOST);
			*temp = '\0';
		}
		else
		{
			snprintf(http_host_long, NI_MAXHOST, "%s:%s",
				http_host, cursock->port);
		}
	}
	if (cursock->socketname)
	{
		/* for socket with sockname - only use matching vhost section */
		for (current = config.virtual; current; current = current->next)
			if (current->socketname &&
					!strcasecmp(cursock->socketname, current->socketname))
			{
				/* found matching socketname - look for matching hostname */
				/* this duplicates code below: maybe use a function? */
				if (current->hostname &&
					(!strcasecmp(http_host_long, current->hostname) ||
					 !strcasecmp(http_host, current->hostname)))
					break;
				else if (current->aliases)
				{
					char	**aliasp;
					for (aliasp = current->aliases; *aliasp; aliasp++)
						if (!strcasecmp(http_host_long, *aliasp) ||
								!strcasecmp(http_host, *aliasp))
							break;
					if (*aliasp)
						break;
				}
			}
		if (!current)
			/* if no hostname matches - find the first matching socketname */
			for (current = config.virtual; current; current = current->next)
				if (current->socketname &&
						!strcasecmp(cursock->socketname, current->socketname))
					break;
		/* if no match was found: fall-through to system default */
	}
	else
	{
		/* check all vhosts */
		for (current = config.virtual; current; current = current->next)
		{
			if (current->socketname)
				continue;
			if (!strcasecmp(http_host_long, current->hostname) ||
					!strcasecmp(http_host, current->hostname))
				break;
			else if (current->aliases)
			{
				char	**aliasp;

				for (aliasp = current->aliases; *aliasp; aliasp++)
					if (!strcasecmp(http_host_long, *aliasp) ||
							!strcasecmp(http_host, *aliasp))
						break;
				if (*aliasp)
					break;
			}
		}
	}
	if (config.usestricthostname &&
			!current &&
			strcasecmp(http_host, config.system->hostname))
	{
		char	**aliasp = NULL;

		if ((aliasp = config.system->aliases))
			for (; *aliasp; aliasp++)
			{
				if (!strcasecmp(http_host, *aliasp))
					break;
			}
		if (!aliasp || !*aliasp)
		{
			xserror(400, "Unknown Host");
			return;
		}
	}
	if (params[0] && params[1] == '~')
		current = config.users;
	else if (!current)
		current = config.system;

	/* always set stderr to the appropriate logfile */
	if (current->openerror)
		dup2(fileno(current->openerror), 2);

METHOD:
	setenv("REQUEST_METHOD", line, 1);
	setenv("REQUEST_URI", params, 1);
	if (!strcasecmp("GET", line))
		do_get(params);
	else if (!strcasecmp("HEAD", line))
		do_head(params);
	else if (!strcasecmp("POST", line))
		do_post(params);
	else if (!strcasecmp("OPTIONS", line))
		do_options(params);
	else if (!strcasecmp("TRACE", line))
		do_trace(params);
	else if (!strcasecmp("PUT", line))
		do_put(params);
	else if (!strcasecmp("DELETE", line))
		do_delete(params);
	else
		xserror(400, "Unknown method");
}

static	void
standalone_main()
{
	char			id = 'B';

	detach();
	write_pidfile();
	open_logs(0);

	/* start with second socket - the first will be last */
	for (cursock = config.sockets->next; cursock; cursock = cursock->next)
	{
		/* spawn auxiliary master */
		switch (fork())
		{
		case -1:
			warn("fork()");
			killpg(0, SIGTERM);
			exit(1);
		case 0:
			mainhttpd = false;
			standalone_socket(id);
			/* NOTREACHED */
		default:
			id++;
		}
	}
	/* make myself useful */
	cursock = config.sockets;
	standalone_socket('A');
	/* NOTREACHED */
}

static	void
standalone_socket(int id)
{
	int			csd = 0;
	unsigned int		count;
	socklen_t		clen;
#ifdef		HAVE_GETADDRINFO
	struct	addrinfo	hints, *res;
	struct	sockaddr_storage	saddr;
#else		/* HAVE_GETADDRINFO */
	struct	sockaddr	saddr;
	in_port_t		sport;
#endif		/* HAVE_GETADDRINFO */
#ifndef		HAVE_GETNAMEINFO
	in_addr_t		laddr;
#endif		/* HAVE_GETNAMEINFO */
	pid_t			*childs;

	setproctitle("xs(MAIN): Initializing deamons...");

#ifdef		HAVE_GETADDRINFO
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = cursock->family;
# ifdef		__linux__
	if (PF_UNSPEC == cursock->family)
		hints.ai_family = PF_INET6;
# endif		/* __linux__ */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((getaddrinfo(cursock->address ? cursock->address : NULL,
			cursock->port, &hints, &res)))
		err(1, "getaddrinfo()");

	/* only look at the first address */
	if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
		err(1, "socket()");
#else		/* HAVE_GETADDRINFO */
	if ((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");
#endif		/* HAVE_GETADDRINFO */

#ifdef		SO_REUSEPORT
	if ((setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (int[]){1}, sizeof(int))) == -1)
		err(1, "setsockopt(REUSEPORT)");
#else		/* SO_REUSEPORT */
# ifdef		SO_REUSEADDR
	if ((setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int))) == -1)
		err(1, "setsockopt(REUSEADDR)");
# endif		/* SO_REUSEADDR */
#endif		/* SO_REUSEPORT */

	if ((setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (int[]){1}, sizeof(int))) == -1)
		err(1, "setsockopt(KEEPALIVE)");

	if ((setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (int[]){RWBUFSIZE}, sizeof(int))) == -1)
		err(1, "setsockopt(SNDBUF)");
	if ((setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (int[]){RWBUFSIZE}, sizeof(int))) == -1)
		err(1, "setsockopt(SNDBUF)");

#ifdef		HAVE_GETADDRINFO
	if (bind(sd, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "bind()");

	freeaddrinfo(res);

#else		/* HAVE_GETADDRINFO */
	/* Quick patch to run on old systems */
	memset(&saddr, 0, sizeof(struct sockaddr));
	saddr.sa_family = PF_INET;
	if (!strcmp(cursock->port, "http"))
		sport = 80;
	else if (!strcmp(cursock->port, "https"))
		sport = 443;
	else
		sport = (in_port_t)strtoul(cursock->port, NULL, 10) || 80;
	((struct sockaddr_in *)&saddr)->sin_port = htons(sport);

	if (bind(sd, &saddr, sizeof(struct sockaddr)) == -1)
		err(1, "bind()");
#endif		/* HAVE_GETADDRINFO */

	if (listen(sd, MAXLISTEN))
		err(1, "listen()");

	if (config.useacceptfilter)
	{
		/* can only be called after listen() */
#ifdef		SO_ACCEPTFILTER
		struct	accept_filter_arg	afa = { .af_name = "httpready" };

		if ((setsockopt(sd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa))) == -1)
		{
			warn("setsockopt(ACCEPTFILTER) - missing accf_http(9)?");
			strcpy(afa.af_name, "dataready");
			if ((setsockopt(sd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa))) == -1)
				warn("setsockopt(ACCEPTFILTER) - missing accf_data(9)?");
		}
#else		/* SO_ACCEPTFILTER */
# ifdef		TCP_DEFER_ACCEPT
		if ((setsockopt(sd, SOL_TCP, TCP_DEFER_ACCEPT, (int[]){180}, sizeof(int))) == -1)
			warn("setsockopt(TCP_DEFER_ACCEPT)");
# endif		/* TCP_DEFER_ACCEPT */
#endif		/* SO_ACCEPTFILTER */
	}

#ifdef		HAVE_SETRLIMIT
	/* local block */
	{
		const struct	rlimit		limit =
			{ .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };

# ifdef		RLIMIT_NPROC
		setrlimit(RLIMIT_NPROC, &limit);
# endif		/* RLIMIT_NPROC */
# ifdef		RLIMIT_CPU
		setrlimit(RLIMIT_CPU, &limit);
# endif		/* RLIMIT_CPU */
	}
#endif		/* HAVE_SETRLIMIT */

	set_signals();
	reqs = 0;
	MALLOC(childs, pid_t, cursock->instances);

	for (count = 0; count < cursock->instances; count++)
	{
		pid_t	pid;

		switch (pid = fork())
		{
		case -1:
			warn("fork()");
			killpg(0, SIGTERM);
			exit(1);
		case 0:
			mainhttpd = false;
			goto CHILD;
		default:
			childs[count] = pid;
		}
	}

	fflush(stdout);
	while (true)
	{
		setproctitle("xs(MAIN-%c): Waiting for dead children", id);
		while (mysleep(30))
			/* NOTHING HERE */;
		setproctitle("xs(MAIN-%c): Searching for dead children", id);
		for (count = 0; count < cursock->instances; count++)
		{
			if (kill(childs[count], 0))
			{
				pid_t	pid;

				fflush(stdout);
				switch(pid = fork())
				{
				case -1:
					warn("fork()");
					break;
				case 0:
					mainhttpd = false;
					goto CHILD;
				default:
					childs[count] = pid;
				}
			}
		}
	}

	CHILD:
	setvbuf(stdout, NULL, _IOFBF, 0);
	while (true)
	{
		struct	linger	sl;

		/* (in)sanity check */
		if (count > cursock->instances)
		{
			const	char	*env;

			env = getenv("QUERY_STRING");
			errx(1, "[%s] httpd(pid %" PRIpid "): MEMORY CORRUPTION [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']",
				currenttime, getpid(),
				remotehost[0] ? remotehost : "(none)",
				orig[0] ? orig : "(none)", env ? env : "(none)",
				current ? current->hostname : config.system->hostname,
				referer[0] ? referer : "(none)");
		}

		setproctitle("xs(%c%d): [Reqs: %06d] Setting up myself to accept a connection",
			id, count + 1, reqs);
		if (!origeuid && (seteuid(origeuid) == -1))
			err(1, "seteuid(%" PRIuid ") failed", origeuid);
		if (!origeuid && (setegid(origegid) == -1))
			err(1, "setegid(%" PRIuid ") failed", origegid);
		filedescrs();
		setproctitle("xs(%c%d): [Reqs: %06d] Waiting for a connection...",
			id, count + 1, reqs);
		clen = sizeof(saddr);
		if ((csd = accept(sd, (struct sockaddr *)&saddr, &clen)) < 0)
		{
			mysleep(1);
			if (errno == EINTR)
				child_handler(SIGCHLD);
			if (errno == EBADF || errno == EFAULT)
				err(1, "accept()");
			continue;
		}
		setproctitle("xs(%c%d): [Reqs: %06d] accept() gave me a connection...",
			id, count + 1, reqs);
		if (fcntl(csd, F_SETFL, 0))
			warn("fcntl()");

		sl.l_onoff = 1; sl.l_linger = 10;
		if (setsockopt(csd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0)
			warnx("setsockopt(SOL_SOCKET)");

		dup2(csd, 0); dup2(csd, 1);
		close(csd);

		setvbuf(stdin, NULL, _IONBF, 0);

		strlcpy(remoteaddr, "0.0.0.0", NI_MAXHOST);
#ifdef		HAVE_GETNAMEINFO
		if (!getnameinfo((struct sockaddr *)&saddr, clen,
			remoteaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
		{
			/* Fake $REMOTE_ADDR because most people don't
			 * (want to) understand ::ffff: adresses.
			 */
			if (!strncmp(remoteaddr, "::ffff:", 7))
				memmove(remoteaddr, remoteaddr + 7, strlen(remoteaddr) - 7);
		}
#else		/* HAVE_GETNAMEINFO */
		/* I don't need libnsl for this... */
		laddr = ntohl(((struct sockaddr_in *)&saddr)->sin_addr.s_addr);
		snprintf(remoteaddr, NI_MAXHOST, "%d.%d.%d.%d",
			(laddr & 0xff000000) >> 24,
			(laddr & 0x00ff0000) >> 16,
			(laddr & 0x0000ff00) >> 8,
			(laddr & 0x000000ff));
#endif		/* HAVE_GETNAMEINFO */

		strlcpy(remotehost, remoteaddr, NI_MAXHOST);
		if (config.usednslookup)
		{
#ifdef		HAVE_GETNAMEINFO
			getnameinfo((struct sockaddr *)&saddr, clen,
				remotehost, NI_MAXHOST, NULL, 0, 0);
#else		/* HAVE_GETNAMEINFO */
# ifdef		HAVE_GETADDRINFO
			/* This is especially for broken Linux distro's
			 * that don't understand what getnameinfo() does
			 * Let's abuse getaddrinfo() instead...
			 */
			hints.ai_family = PF_INET;
			hints.ai_flags = AI_CANONNAME;
			if (!getaddrinfo(remoteaddr, NULL, &hints, &res))
			{
				strlcpy(remotehost, res->ai_canonname, NI_MAXHOST);
				freeaddrinfo(res);
			}
# else		/* HAVE_GETADDRINFO */
			/* Loooser! You will just have to use the IP-adres... */
# endif		/* HAVE_GETADDRINFO */
#endif		/* HAVE GETNAMEINFO */
		}
		if (!initssl())
			continue;
		setproctitle("xs(%c%d): Connect from `%s'",
			id, count + 1, remotehost);
		setcurrenttime();
		initreadmode(true);
		alarm(20);
		reqsc = 1;
		in_progress = false;
		if (message503[0])
			secprintf("HTTP/1.1 503 Busy\r\n"
				"Content-type: text/plain\r\n"
				"Content-length: %zu\r\n\r\n%s",
				strlen(message503), message503);
		else
			do
			{
				process_request();
				alarm(10);
				if (chunked)
				{
					chunked = false;
#ifdef		HAVE_LIBMD
					if (md5context)
					{
						char   digest[MD5_DIGEST_LENGTH];
						char           base64_data[MD5_DIGEST_B64_LENGTH];

						MD5Final((unsigned char *)digest, md5context);
						base64_encode(digest, MD5_DIGEST_LENGTH, base64_data);
						secprintf("0\r\nContent-MD5: %s\r\n\r\n", base64_data);
						free(md5context);
					}
					else
#endif		/* HAVE_LIBMD */
						secputs("0\r\n\r\n");
				}
				setproctitle("xs(%c%d): Awaiting request "
					"#%d from `%s'",
					id, count + 1, ++reqsc, remotehost);
				in_progress = false;
			}
			while (persistent && fflush(stdout) != EOF);
		reqs++;
		alarm(0);
		endssl();
		fflush(stdout); fflush(stdin); fflush(stderr);
		close(csd);
	}
	/* NOTREACHED */
}

static	void
setup_environment()
{
	/* start with empty environment */
	CLEANENV;

	setenv("SERVER_SOFTWARE", SERVER_IDENT, 1);
	setenv("SERVER_NAME", config.system->hostname, 1);
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	setenv("HTTPD_ROOT", config.systemroot, 1);
	setenv("SERVER_PORT",
		!strcmp(cursock->port, "http") ? "80" :
		!strcmp(cursock->port, "https") ? "443" :
		cursock->port, 1);
	setenv("REMOTE_ADDR", remoteaddr, 1);
	setenv("REMOTE_HOST", remotehost, 1);
	ssl_environment();
}

int
main(int argc, char **argv, char **envp)
{
	int			option;
	size_t		num;
	bool		nolog = false;
	enum		{ opt_port, opt_dir, opt_host };
	char		*longopt[] = { [2] = NULL };
	uid_t		uid = 0;
	gid_t		gid = 0;

	origeuid = geteuid(); origegid = getegid();
	memset(&config, 0, sizeof config);

	num = 0;
	for (option = 0; option < argc; option++)
		num += (1 + strlen(argv[option]));
	MALLOC(startparams, char, num);
	startparams[0] = '\0';
	for (option = 0; option < argc; option++)
	{
		strlcat(startparams, argv[option], num);
		if (option < argc - 1)
			strlcat(startparams, " ", num);
	}

	message503[0] = '\0';
#ifdef		PATH_PREPROCESSOR
	strlcpy(config_preprocessor, PATH_PREPROCESSOR, XS_PATH_MAX);
#else		/* Not PATH_PREPROCESSOR */
	config_preprocessor[0] = '\0';
#endif		/* PATH_PREPROCESSOR */
	strlcpy(config_path, calcpath(HTTPD_CONF), XS_PATH_MAX);
	while ((option = getopt(argc, argv, "a:c:d:g:m:n:p:u:NP:v")) != EOF)
	{
		switch(option)
		{
		case 'a':	/* address */
			longopt[opt_host] = optarg;
			break;
		case 'c':	/* configfile */
			strlcpy(config_path, optarg, XS_PATH_MAX);
			break;
		case 'd':	/* rootdir */
			if (*optarg != '/')
				errx(1, "The -d directory must start with a /");
			longopt[opt_dir] = optarg;
			break;
		case 'g':	/* group */
		{
			const struct group	*groupinfo;

			if ((gid = strtoul(optarg, NULL, 10)) > 0)
				break;
			if (!(groupinfo = getgrnam(optarg)))
				errx(1, "Invalid group ID");
			gid = groupinfo->gr_gid;
			break;
		}
		case 'm':	/* message */
			strlcpy(message503, optarg, MYBUFSIZ);
			break;
		case 'n':	/* num. proceses */
			if (!(config.instances = strtoul(optarg, NULL, 10)))
				errx(1, "Invalid number of processes");
			break;
		case 'p':	/* port */
			longopt[opt_port] = optarg;
			break;
		case 'u':	/* user */
		{
			const struct passwd	*userinfo;

			if ((uid = strtoul(optarg, NULL, 10)) > 0)
				break;
			if (!(userinfo = getpwnam(optarg)))
				errx(1, "Invalid user ID");
			uid = userinfo->pw_uid;
			break;
		}
		case 'N':	/* nolog */
			nolog = true;
			strlcpy(config_path, BITBUCKETNAME, XS_PATH_MAX);
			break;
	 	case 'P':	/* preprocessor */
			strlcpy(config_preprocessor, optarg, XS_PATH_MAX);
			break;
		case 'v':	/* version */
			printf("%s", SERVER_IDENT);
#ifdef		HAVE_UNAME
			{
				struct utsname		utsname;

				uname(&utsname);
				printf(" %s/%s", utsname.sysname,
					utsname.release);
			}
#endif		/* HAVE_UNAME */
#ifdef		OPENSSL_VERSION_NUMBER
			printf(" OpenSSL/%d.%d.%d",
				(int)(OPENSSL_VERSION_NUMBER >> 28 & 0xf),
				(int)(OPENSSL_VERSION_NUMBER >> 20 & 0xff),
				(int)(OPENSSL_VERSION_NUMBER >> 12 & 0xff));
# if		OPENSSL_VERSION_NUMBER >> 4 & 0xff
			putchar('a' - 1 + (unsigned char)(OPENSSL_VERSION_NUMBER >> 4 & 0xff));
# endif
#endif		/* OPENSSL_VERSION_NUMBER */
#ifdef		PCRE_MAJOR
			printf(" PCRE/%u.%u", PCRE_MAJOR, PCRE_MINOR);
#endif		/* PCRE_MINOR */
			printf("\nCompiled options:\n\t"
#ifdef		HANDLE_SSL
				"+SSL "
#else		/* HANDLE_SSL */
				"-SSL "
#endif		/* HANDLE_SSL */
#ifdef		HAVE_CRYPT
				"+CRYPT "
#else		/* HAVE_CRYPT */
				"-CRYPT "
#endif		/* HAVE_CRYPT */
#ifdef		HAVE_LIBMD
 				"+MD "
#else		/* HAVE_LIBMD */
				"-MD "
#endif		/* HAVE_LIBMD */
#ifdef		HAVE_PCRE
				"+PCRE "
#else		/* HAVE_PCRE */
				"-PCRE "
#endif		/* HAVE_PCRE */
#ifdef		HAVE_PERL
				"+PERL "
#else		/* HAVE_PERL */
				"-PERL "
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
				"+PYTHON "
#else		/* HAVE_PYTHON */
				"-PYTHON "
#endif		/* HAVE_PYTHON */
#ifdef		AUTH_LDAP
				"+LDAP "
#else		/* AUTH_LDAP */
				"-LDAP "
#endif		/* AUTH_LDAP */
#ifdef		HAVE_CURL
				"+CURL "
#else		/* HAVE_CURL */
				"-CURL "
#endif		/* HAVE_CURL */
#ifdef		HAVE_SSP
				"+SSP "
#else		/* HAVE_SSP */
				"-SSP "
#endif		/* HAVE_SSP */
#ifdef		HAVE_GDB
				"+GDB "
#endif		/* HAVE_GDB */
				"\nDefault configuration file:\n"
#ifdef		PATH_PREPROCESSOR
				"\t%s %s\n", config_preprocessor, config_path
#else		/* PATH_PREPROCESSOR */
				"\t%s\n", config_path
#endif		/* PATH_PREPROCESSOR */
				);
			return 0;
		default:
			errx(1, "Usage: httpd [-u username] [-g group] [-p port] [-n number]\n[-d rootdir] [-m service-message] [-v]");
		}
	}
	load_config();
	/* sanity chck */
	counter_versioncheck();

#ifdef		HAVE_SETPRIORITY
	if (setpriority(PRIO_PROCESS, (pid_t)0, config.priority))
		warn("setpriority()");
#endif		/* HAVE_SETPRIORITY */

	/* Explicity set these, overriding default or implicit setting */
#define	SET_OPTION(option, config) \
	if (longopt[option]) { \
		if (config) \
			free(config); \
		config = strdup(longopt[option]); \
	}

	if (nolog)
	{
		config.pidfile =
			config.system->logaccess =
			config.system->logreferer =
			config.system->logerror =
			strdup(BITBUCKETNAME);
		config.system->logscript = NULL;
	}
	if (config.sockets)
		SET_OPTION(opt_port,  config.sockets[0].port);
	SET_OPTION(opt_dir,  config.systemroot);
	SET_OPTION(opt_host, config.system->hostname);
	if (uid)
		config.system->userid = uid;
	if (gid)
		config.system->groupid = gid;

#ifndef		HAVE_SETPROCTITLE
	initproctitle(argc, argv, envp);
#endif		/* HAVE_SETPROCTITLE */
	initnonce();
	initfcgi();
	CLEANENV;

	standalone_main();
	/* NOTREACHED */
	(void)envp;
	(void)copyright;
}
