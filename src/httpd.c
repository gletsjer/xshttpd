/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<inttypes.h>
#include	<sys/resource.h>
#include	<sys/mman.h>
#include	<sys/socket.h>
#include	<sys/wait.h>
#include	<sys/signal.h>
#include	<sys/stat.h>
#include	<sys/utsname.h>
#include	<sys/file.h>
#include	<sys/select.h>
#include	<sys/param.h>
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
#include	<resolv.h>
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
#include	<fnmatch.h>
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
#include	"malloc.h"
#include	"fcgi.h"
#include	"modules.h"
#include	"hash.h"

static char copyright[] = "Copyright 1995-2009 Sven Berkvens, Johan van Selst";

/* Global variables */

static	int	sd, reqs, reqsc;
static	bool	mainhttpd = true, in_progress = false;
bool		runasroot = false;
char		currenttime[80];
static	char	remoteaddr[NI_MAXHOST], remotehost[NI_MAXHOST];
static	char	referer[MYBUFSIZ], orig[MYBUFSIZ];
static	char	*startparams, *message503;
struct	session		session;
struct	env		env;

/* Prototypes */

static	void	filedescrs		(void);
static	void	detach			(void);
static	void	setcurrenttime		(void);
static	void	child_handler		(int);
static	void	term_handler		(int)	NORETURN;
static	bool	write_pidfile		(pid_t);
static	void	open_logs		(int);
static	void	core_handler		(int)	NORETURN;
static	void	set_signals		(void);

static	void	process_request		(void);

static	void	setup_environment	(void);
static	void	standalone_main		(void)	NORETURN;
static	void	standalone_socket	(int)	NORETURN;

static	bool	addr_equal
	(const void * const socka, const void * const sockb)	CONST_FUNC;

static	void
filedescrs()
{
	close(STDIN_FILENO);
	if (open(BITBUCKETNAME, O_RDONLY, 0) != 0)
		err(1, "Cannot open fd 0 (%s)", BITBUCKETNAME);
	if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
		err(1, "Cannot dup2() fd 1");
}

static	void
detach()
{
	const pid_t		pid = fork();

	if (pid > 0)
	{
		if (!write_pidfile(pid))
		{
			kill(pid, SIGTERM);
			exit(1);
		}
		exit(0);
	}
	else if (pid == -1)
		err(1, "fork()");
	if (chdir("/"))
		err(1, "chdir(`/')");
#ifdef		HAVE_SETSID
	if (setsid() == -1)
		err(1, "setsid() failed");
#else		/* Not HAVE_SETSID */
	if (setpgrp(getpid(), 0) == -1)
		err(1, "setpgrp() failed");
#endif		/* HAVE_SETSID */
}

static void
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

static	bool
write_pidfile(pid_t pid)
{
	FILE		*pidlog;
	int		pidlock;

	if (!mainhttpd)
		return true;

#ifdef		O_EXLOCK
	pidlock = open(config.pidfile,
		O_WRONLY | O_TRUNC | O_CREAT | O_NONBLOCK | O_EXLOCK,
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	if ((pidlock < 0) && (EOPNOTSUPP == errno))
#endif		/* O_EXLOCK */
		pidlock = open(config.pidfile,
			O_WRONLY | O_TRUNC | O_CREAT,
			S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);

	if ((pidlock < 0) || !(pidlog = fdopen(pidlock, "w")))
	{
		warn("Cannot open pidfile `%s'", config.pidfile);
		return false;
	}

	fprintf(pidlog, "%" PRIpid "\n%s\n", pid, startparams);
	fflush(pidlog);
	return true;
}

static void
reopen_log(FILE **fp, const char * const filename)
{
	FILE	*openlog = *fp;

	if (!filename)
		return;

	/* Open new log first, then close old one
	 * When rotating logs the file should be moved before sending HUP
	 */
	if ('|' != filename[0])
	{
		if (!(*fp = fopen(filename, "a")))
			err(1, "fopen(`%s' [append])", current->logaccess);
		if (openlog)
			fclose(openlog);
	}
	else /* use_pipe */
	{
		if (!(*fp = popen(filename + 1, "w")))
			err(1, "popen(`%s' [write])", filename);
		if (openlog)
			pclose(openlog);
	}
	setvbuf(*fp, NULL, _IOLBF, 0);
}

static	void
open_logs(int sig)
{
	const uid_t		savedeuid = geteuid();
	const gid_t		savedegid = getegid();

	if (sig)
	{
		remove_config();
		load_config();
	}
	if (runasroot)
		seteugid(0, 0);
	if (mainhttpd)
	{
		/* the master reloads, the children die */
		signal(SIGHUP, SIG_IGN);
		killpg(0, SIGHUP);
	}

	for (current = config.system; current; current = current->next)
	{
		/* max. four logfiles per vhost */
		reopen_log(&current->openaccess, current->logaccess);
		if (current->logstyle == log_traditional)
			reopen_log(&current->openreferer, current->logreferer);
		reopen_log(&current->openerror, current->logerror);
		reopen_log(&current->openscript, current->logscript);
	}

	fflush(stderr);
	close(STDERR_FILENO);

	if (config.system->openerror)
	{
		const int	tempfile = fileno(config.system->openerror);

		if (tempfile != STDERR_FILENO)
		{
			if (dup2(tempfile, STDERR_FILENO) == -1)
				err(1, "dup2() failed");
		}
	}
	else
		config.system->openerror = stderr;

	if (mainhttpd)
	{
		setcurrenttime();
		fprintf(stderr, "[%s] Successful restart\n", currenttime);
	}
	loadfiletypes(NULL, NULL);
	loadcompresstypes();
	loadscripttypes(NULL, NULL);

#ifdef		HAVE_CURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif		/* HAVE_CURL */
	set_signals();
	if (runasroot)
		seteugid(savedeuid, savedegid);
}

void
alarm_handler(int sig)
{
	alarm(0);
	if (!in_progress)
	{
		fflush(stdout); fflush(stdin); fflush(stderr);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		session.persistent = false;
		return;
	}
	(void)sig;
	exit(1);
}

static	void
core_handler(int sig)
{
	alarm(0); setcurrenttime();
	errx(1, "[%s] httpd(pid % " PRIpid "): FATAL SIGNAL %d [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']",
		currenttime, getpid(), sig,
		env.remote_host ? env.remote_host : "(none)",
		orig[0] ? orig : "(none)",
		env.query_string ? env.query_string : "(none)",
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
xserror(int code, const char * const format, ...)
{
	va_list		ap;
	char		*errmsg = NULL;
	char		*message, *htmlmessage;

	alarm(180);
	va_start(ap, format);
	VASPRINTF(&message, format, ap);
	va_end(ap);

	/* message should not contain html */
	htmlmessage = escape(message);

	/* log error */
	fprintf((current && current->openerror) ? current->openerror : stderr,
		"[%s] httpd(pid %" PRIpid "): %03d %s [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']\n",
		currenttime, getpid(), code, message,
		env.remote_host ? env.remote_host : "(none)",
		orig[0] ? orig : "(none)",
		env.query_string ? env.query_string : "(none)",
		current ? current->hostname : config.system->hostname,
		referer[0] ? referer : "(none)");
	fflush(stderr);

	if (599 == code)
	{
		/* connection closed: don't send error */
		FREE(message);
		FREE(htmlmessage);
		return;
	}

	/* display error */
	if (!session.headonly)
	{
		ASPRINTF(&errmsg,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
			"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n\n"
			"<head><title>%03d %s</title></head>\n"
			"<body><h1>%03d %s</h1></body></html>\n",
			code, htmlmessage,
			code, htmlmessage);
	}
	if (session.headers)
	{
		struct maplist	*rh = &session.response_headers;
		const char	*header;

		maplist_free(rh);
		maplist_append(rh, append_prepend,
			"Status", "%03d %s", code, message);
		if (config.usetimestamp)
			maplist_append(rh, append_replace,
				"Date", "%s", currenttime);
		if (config.serverident)
			maplist_append(rh, append_replace,
				"Server", "%s", config.serverident);

		session.size = errmsg ? strlen(errmsg) : 0;
		if ((header = getenv("HTTP_ALLOW")))
			maplist_append(rh, append_default,
				"Allow", "%s", header);
		if ((header = getenv("HTTP_CONTENT_RANGE")))
			maplist_append(rh, append_default,
				"Content-range", "%s", header);

		if (!writeheaders())
		{
			/* Write failed: don't write the rest */
			session.headonly = true;
			session.persistent = false;
		}
	}
	if (!session.headonly)
	{
		secputs(errmsg);
		FREE(errmsg);
	}
	FREE(message);
	FREE(htmlmessage);
}

void
redirect(const char * const redir, const unsigned int status, const xs_redirflags_t flags)
{
	const char	*qs = NULL;
	char		*qsurl = NULL,
			*redirdec,
			*redirhtml,
			*redirurl;
	char		*errmsg = NULL;

	redirdec = urldecode(redir);
	redirurl = urlencode(redirdec, false);
	redirhtml = escape(redir);
	if (flags & redir_env) {
		qs = env.query_string;
		qsurl = urlencode(qs, false);
	}
	if (!session.headonly)
	{
		ASPRINTF(&errmsg,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
			"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
			"<head><title>Document has moved</title></head>\n"
			"<body><h1>Document has moved</h1>\n"
			"<p>This document has %smoved to "
			"<a href=\"%s%s%s\">%s</a>.</p></body></html>\n",
			status == 301 || status == 308 ? "permanently " : "",
			redirurl, qs ? "?" : "", qs ? qsurl : "", redirhtml);
	}
	if (session.headers)
	{
		struct maplist	*rh = &session.response_headers;

		maplist_append(rh, append_prepend | append_replace,
			"Status",
			status == 301 ? "%d Moved Permanently" :
			status == 302 ? "%d Found" :
			status == 303 ? "%d See Other" :
			status == 307 ? "%d Temporary Redirect" :
			status == 308 ? "%d Permanent Redirect" :
			"%d Redirect",
			status);
		if (qs)
			maplist_append(rh, append_default,
				"Location", "%s?%s", redirurl, qsurl);
		else
			maplist_append(rh, append_default,
				"Location", "%s", redirurl);
		session.size = errmsg ? strlen(errmsg) : 0;
		writeheaders();
	}
	session.rstatus = status;
	if (!session.headonly)
		secputs(errmsg);
	FREE(errmsg);
	FREE(redirhtml);
	FREE(redirdec);
	FREE(redirurl);
	FREE(qsurl);
	fflush(stdout);
}

void
server_error(int code, const char * const readable, const char * const cgi)
{
	char		*cgipath = NULL, *errmsg = NULL;
	const char	filename[] = "/error";

	if (!current)
		current = config.system;
	if (session.headonly || getenv("ERROR_CODE"))
	{
		xserror(code, "%s", readable);
		return;
	}
	setenv("ERROR_CODE", cgi, 1);
	ASPRINTF(&errmsg, "%03d %s", code, readable);
	setenv("ERROR_READABLE", errmsg, 1);
	FREE(errmsg);
	setenv("ERROR_URL", orig, 1);
	setenv("ERROR_URL_EXPANDED", convertpath(orig), 1);
	if (orig[0])
	{
		char	*url = escape(orig);
		setenv("ERROR_URL_ESCAPED", url, 1);
		FREE(url);
	}
	else
		setenv("ERROR_URL_ESCAPED", "", 1);
	/* Look for user-defined error script */
	if (current == config.users)
	{
		const char * const username = getenv("USER");

		if (username)
		{
			char	*tpath = NULL;

			ASPRINTF(&tpath, "/~%s/%s%s",
				username, current->execdir, filename);
			STRDUP(cgipath, convertpath(tpath));
			FREE(tpath);
		}
	}
	else	/* Look for virtual host error script */
	{
		ASPRINTF(&cgipath, "%s/%s", current->phexecdir, filename);
	}

	/* local block */
	{
		struct	stat		statbuf;

		if (stat(cgipath, &statbuf))
		{
			/* Last resort: try system error script */
			FREE(cgipath);
			ASPRINTF(&cgipath, "%s/%s", config.system->phexecdir, filename);
			if (stat(cgipath, &statbuf))
			{
				xserror(code, "%s", readable);
				FREE(cgipath);
				return;
			}
		}
	}

	/* local block */
	{
		char	*temp = strrchr(cgipath, '/');
		if (temp)
			*temp = '\0';
	}
	fprintf((current && current->openerror) ? current->openerror : stderr,
		"[%s] httpd(pid %" PRIpid "): %03d %s [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']\n",
		currenttime, getpid(), code, readable,
		env.remote_host ? env.remote_host : "(none)",
		orig[0] ? orig : "(none)",
		env.query_string ? env.query_string : "(none)",
		current ? current->hostname : config.system->hostname,
		referer[0] ? referer : "(none)");

	/* execute error cgi */
	const bool	waspost = session.postonly;
	session.postonly = false;
	/* POST should not be redirected to the error CGI
	 * XXX: close the input here to avoid access?
	 */

	do_script(orig, cgipath, filename, NULL);
	session.postonly = waspost;
	FREE(cgipath);
}

void
logrequest(const char * const request, off_t size)
{
	char		*dynrequest, *dynagent, *dynuser, *p;
	const char	*timestamp = gmtimestamp();
	FILE		*alog;

	if (!current)
	{
		warnx("Failed to log request without context");
		return;
	}

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

	STRDUP(dynrequest, request);
	if (dynrequest)
		for (p = dynrequest; *p; p++)
			if ('\"' == *p)
				*p = '\'';

	dynagent = getenv("USER_AGENT");
	STRDUP(dynagent, dynagent ? dynagent : "-");
	for (p = dynagent; *p; p++)
		if ('\"' == *p)
			*p = '\'';

	dynuser = getenv("REMOTE_USER");
	STRDUP(dynuser, dynuser ? dynuser : "-");
	for (p = dynuser; *p; p++)
		if ('\"' == *p)
			*p = '\'';

	switch (current->logstyle)
	{
	case log_traditional:
		{
		FILE	*rlog = current->openreferer
			? current->openreferer
			: config.system->openreferer;
		fprintf(alog, "%s - %s [%s] \"%s %s %s\" %03d %" PRIoff "\n",
			env.remote_host,
			dynuser,
			timestamp,
			env.request_method, dynrequest,
			env.server_protocol,
			session.rstatus,
			size > 0 ? size : 0);
		if (rlog &&
			(!current->thisdomain || !strcasestr(referer, current->thisdomain)))
			fprintf(rlog, "%s -> %s\n", referer, request);
		}
		break;
	case log_virtual:
		/* this is combined format + virtual hostname */
		fprintf(alog, "%s %s - %s [%s] \"%s %s %s\" %03d %" PRIoff
				" \"%s\" \"%s\"\n",
			current->hostname ? current->hostname : config.system->hostname,
			env.remote_host,
			dynuser,
			timestamp,
			env.request_method, dynrequest,
			env.server_protocol,
			session.rstatus,
			size > 0 ? size : 0,
			referer[0] ? referer : "-",
			dynagent);
		break;
	case log_combined:
		fprintf(alog, "%s - %s [%s] \"%s %s %s\" %03d %" PRIoff
				" \"%s\" \"%s\"\n",
			env.remote_host,
			dynuser,
			timestamp,
			env.request_method, dynrequest,
			env.server_protocol,
			session.rstatus,
			size > 0 ? size : 0,
			referer[0] ? referer : "-",
			dynagent);
		break;
	case log_none:
		/* DO NOTHING */
		break;
	}

	FREE(dynrequest);
	FREE(dynagent);
	FREE(dynuser);
}

ssize_t read_callback(char *, size_t);
ssize_t
read_callback(char *buf, size_t len)
{
	return secread(0, buf, len);
}

static	void
process_request(void)
{
	char		line[LINEBUFSIZE],
			http_host[NI_MAXHOST], http_host_long[NI_MAXHOST],
			*params, *browser, *url, *ver, *headstr;

	setup_environment();

	headstr = NULL;
	session.headers = true;
	session.httpversion = 11;
	env.server_protocol = "HTTP/1.1";
	strlcpy(session.dateformat, "%a %b %e %H:%M:%S %Y", sizeof session.dateformat);

	orig[0] = referer[0] = line[0] = '\0';
	session.headonly = session.postonly = false;
	current = NULL;
	browser = NULL;
	setcurrenttime();

	http_host[0] = '\0';

	session.rstatus = 200;
	errno = 0;
	session.chunked = false;
	session.persistent = false;
	session.trailers = false;
	env.content_length = 0;

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
	case ERR_QUIT:
		/* fatal error: warning should be in logfile,
		 * no use trying to send an error back */
		return;
	default:
		xserror(400, "Unable to read begin of request line");
		return;
	}
	in_progress = true;

	url = line;
	while (*url && (*url > ' '))
		url++;
	*(url++) = '\0';
	while (*url && *url <= ' ')
		url++;
	ver = url;
	while (*ver && (*ver > ' '))
		ver++;
	*(ver++) = '\0';
	while (*ver && *ver <= ' ')
		ver++;

	for (char *p = ver; *p; p++)
		if (*p <= ' ')
			*p-- = '\0';

	alarm(180);
	if (!*ver)
	{
		session.headers = false;
		session.httpversion = 9;
		setenv("SERVER_PROTOCOL", "HTTP/0.9", 1);
		env.server_protocol = getenv("SERVER_PROTOCOL");
	}
	else if (readheaders(0, &session.request_headers) < 0)
	{
		/* Either connection was closed or header rejected;
		 * the only reject reason being buffer exceeded
		 */
		xserror(431, "Request header field too large");
		return;
	}
	else /* HTTP-like protocol with headers */
	{
		/* fill in reserved Status: header */
		maplist_append(&session.request_headers, append_replace,
			"Status", "%s %s %s", line, url, ver);
		/* XXX: implemented protocol handling modules */
		for (struct module *mod, **mods = modules; (mod = *mods); mods++)
			if (mod->protocol_handler && mod->protocol_handler(
					&session.request_headers,
					read_callback, secwrite))
				return;
	}

	if (!strncasecmp(ver, "HTTP/", 5))
	{
		size_t		headlen = 0;

		if (!strncmp(ver + 5, "1.0", 3))
		{
			setenv("SERVER_PROTOCOL", "HTTP/1.0", 1);
			session.httpversion = 10;
		}
		else
		{
			setenv("SERVER_PROTOCOL", "HTTP/1.1", 1);
			session.httpversion = 11;
			session.persistent = true;
		}
		env.server_protocol = getenv("SERVER_PROTOCOL");
		if (!strcasecmp(line, "TRACE"))
		{
			params = url;
			goto METHOD;
		}

		for (size_t sz = 0; sz < session.request_headers.size; sz++)
		{
			const char * const	idx =
				session.request_headers.elements[sz].index;
			const char * const	val =
				session.request_headers.elements[sz].value;

			headlen += strlen(idx) + 2 + strlen(val) + 2;

			if (!sz)
				/* DO NOTHING */;
			else if (!strcasecmp("Content-length", idx))
			{
				env.content_length =
					(off_t)strtoull(val, NULL, 10);
				setenv("CONTENT_LENGTH", val, 1);
			}
			else if (!strcasecmp("Content-type", idx))
				setenv("CONTENT_TYPE", val, 1);
			else if (!strcasecmp("User-agent", idx))
			{
				STRDUP(browser, val);
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
				size_t	lenval = strlen(val);
				strlcpy(referer, val, MYBUFSIZ);
				while (lenval-- > 0 && referer[lenval] <= ' ')
					referer[lenval] = '\0';
				setenv("HTTP_REFERER", referer, 1);
			}
			else if (!strcasecmp("Authorization", idx))
			{
				setenv("HTTP_AUTHORIZATION", val, 1);
				env.authorization = getenv("HTTP_AUTHORIZATION");
			}
			else if (!strcasecmp("Connection", idx))
			{
				if (strcasestr(val, "close"))
					session.persistent = false;
				setenv("HTTP_CONNECTION", val, 1);
			}
			else if (!strcasecmp("TE", idx))
			{
				if (strcasestr(val, "trailers"))
					session.trailers = true;
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

				ASPRINTF(&name, "HTTP_%s", idx);
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
				FREE(name);
			}
		}

		MALLOC(headstr, char, headlen + 1);
		char	*h = headstr;

		for (size_t sz = 0; sz < session.request_headers.size; sz++)
		{
			h += sprintf(h, "%s: %s\r\n",
				session.request_headers.elements[sz].index,
				session.request_headers.elements[sz].value);
		}
	}
	else /* strlen(ver) > 0 */
	{
		session.httpversion = 11;
		setenv("SERVER_PROTOCOL", "HTTP/1.1", 1);
		env.server_protocol = getenv("SERVER_PROTOCOL");
		xserror(400, "Unknown protocol");
		/* not persistent */
		return;
	}

	if (!getenv("CONTENT_LENGTH"))
	{
		const char * const	te = getenv("HTTP_TRANSFER_ENCODING");

		if (session.httpversion >= 11 &&
			(!strcasecmp("POST", line) || !strcasecmp("PUT", line)) &&
			(!te || strcasecmp(te, "chunked")))
		{
			xserror(411, "Length Required");
			if (browser)
				FREE(browser);
			return;
		}
		if (!strcasecmp("POST", line) || !strcasecmp("PUT", line))
			setenv("CONTENT_LENGTH", "0", 1);
	}
	if (!browser)
	{
		setenv("USER_AGENT", "UNKNOWN", 1);
		setenv("HTTP_USER_AGENT", "UNKNOWN", 1);
		setenv("USER_AGENT_SHORT", "UNKNOWN", 1);
	}
	else
		FREE(browser);

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
		temp = strchr(http_host, '\0');
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
	else if (session.httpversion >= 11)
	{
		xserror(400, "Missing Host Header");
		return;
	}

	/* local block */
	{
		char * const	temp = strchr(http_host, ':');

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
				else if (current->aliases &&
						(fnmatch_array(current->aliases, http_host_long, FNM_CASEFOLD) ||
						 fnmatch_array(current->aliases, http_host, FNM_CASEFOLD)))
					break;
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
			else if (current->aliases &&
					(fnmatch_array(current->aliases, http_host_long, FNM_CASEFOLD) ||
					 fnmatch_array(current->aliases, http_host, FNM_CASEFOLD)))
				break;
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
			FREE(headstr);
			return;
		}
	}
	if (params[0] && params[1] == '~')
	{
		if (current && !current->allowusers)
		{
			xserror(404, "User is unknown");
			FREE(headstr);
			return;
		}
		current = config.users;
	}
	else if (!current)
		current = config.system;

	/* always set stderr to the appropriate logfile */
	if (current->openerror)
		dup2(fileno(current->openerror), STDERR_FILENO);

METHOD:
	setenv("REQUEST_METHOD", line, 1);
	setenv("REQUEST_URI", params, 1);
	env.request_method = getenv("REQUEST_METHOD");
	env.request_uri = getenv("REQUEST_URI");

	for (struct module *mod, **mods = modules; (mod = *mods); mods++)
		if (mod->http_request)
			mod->http_request(params, headstr);

	/* Fix environment references based on proxy feedback */
	env.remote_addr = getenv("REMOTE_ADDR");
	env.remote_host = getenv("REMOTE_HOST");
	strlcpy(remoteaddr, env.remote_addr, sizeof(remoteaddr));
	strlcpy(remotehost, env.remote_host, sizeof(remotehost));

	struct maplist	*rh = &session.response_headers;
	maplist_append(rh, append_replace, "Status", "200 OK");
	if (config.usetimestamp)
		maplist_append(rh, append_replace, "Date", "%s", currenttime);
	if (config.serverident)
		maplist_append(rh, append_replace, "Server", "%s",
				config.serverident);

	if (!strcasecmp("GET", line))
		do_get(params);
	else if (!strcasecmp("HEAD", line))
		do_head(params);
	else if (!strcasecmp("POST", line))
		do_post(params);
	else if (!strcasecmp("OPTIONS", line))
		do_options(params);
	else if (!strcasecmp("TRACE", line) && config.usetrace)
		do_trace(params);
	else if (!strcasecmp("PUT", line))
		do_put(params);
	else if (!strcasecmp("DELETE", line))
		do_delete(params);
	else
		xserror(400, "Unknown method");

	FREE(headstr);
}

static	void
standalone_main()
{
	char			id = 'B';

	detach();
	open_logs(0);
	if (runasroot)
		seteugid(config.system->userid, config.system->groupid);

	/* initialise modules */
	init_modules();
	module_config();

	for (struct module *mod, **mods = modules; (mod = *mods); mods++)
		if (mod->init)
			mod->init();

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

static bool
addr_equal(const void * const socka, const void * const sockb)
{
	const sa_family_t	fa = ((const struct sockaddr *)socka)->sa_family;
	const sa_family_t	fb = ((const struct sockaddr *)sockb)->sa_family;

	if (fa == AF_INET && fb == AF_INET)
	{
		const struct sockaddr_in * const sia = socka;
		const struct sockaddr_in * const sib = sockb;
		const struct in_addr * const iaa = &sia->sin_addr;
		const struct in_addr * const iab = &sib->sin_addr;

		if (memcmp(iaa, iab, sizeof(struct in_addr)) == 0)
			return true;
	}
	else if (fa == AF_INET6 && fb == AF_INET6)
	{
		const struct sockaddr_in6 * const sia = socka;
		const struct sockaddr_in6 * const sib = sockb;
		const struct in6_addr * const iaa = &sia->sin6_addr;
		const struct in6_addr * const iab = &sib->sin6_addr;

		if (memcmp(iaa, iab, sizeof(struct in6_addr)) == 0)
			return true;
	}

	return false;
}

static	void
standalone_socket(int id)
{
	int			csd = 0;
	unsigned int		count;
#ifdef		HAVE_GETADDRINFO
	struct addrinfo	hints, *res;
#endif		/* HAVE_GETADDRINFO */
#ifdef		HAVE_STRUCT_SOCKADDR_STORAGE
	const socklen_t		salen = sizeof(struct sockaddr_storage);
	struct sockaddr_storage	_saddr;
	struct sockaddr_storage * const saddr = &_saddr;
#else		/* HAVE_STRUCT_SOCKADDR_STORAGE */
	const socklen_t		salen = sizeof(struct sockaddr);
	struct sockaddr		_saddr;
	struct sockaddr * const	saddr = &_saddr;
#endif		/* HAVE_STRUCT_SOCKADDR_STORAGE */
	pid_t			*childs;

	setproctitle("xs(MAIN): Initializing deamons...");

	memset(&env, 0, sizeof(struct env));
	memset(&session, 0, sizeof(struct session));

#ifdef		HAVE_GETADDRINFO
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = cursock->family;
# ifdef		__linux__
	if (PF_UNSPEC == cursock->family)
		hints.ai_family = PF_INET6;
# endif		/* __linux__ */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = cursock->protocol;
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

	if (runasroot && geteuid())
		/* restore root privs */
		seteugid(0, 0);

#ifdef		HAVE_GETADDRINFO
	if (bind(sd, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "bind()");

	freeaddrinfo(res);

#else		/* HAVE_GETADDRINFO */
	{
		/* Quick patch to run on old systems - forced IPv4 */
		const in_port_t		sport;

		memset(saddr, 0, salen);
		saddr->sa_family = PF_INET;
		if (!strcmp(cursock->port, "http"))
			sport = 80;
		else if (!strcmp(cursock->port, "https"))
			sport = 443;
		else
			sport = (in_port_t)strtoul(cursock->port, NULL, 10)
				|| 80;
		((struct sockaddr_in *)saddr)->sin_port = htons(sport);

		if (bind(sd, saddr, sizeof(struct sockaddr_in)) == -1)
			err(1, "bind()");
	}
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
# ifdef		TCP_QUICKACK
		if ((setsockopt(sd, SOL_TCP, TCP_QUICKACK, (int[]){0}, sizeof(int))) == -1)
			warn("setsockopt(TCP_QUICKACK)");
# endif		/* TCP_QUICKACK */
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
	FREE(childs);
	if (runasroot)
		seteugid(config.system->userid, config.system->groupid);
	setvbuf(stdout, NULL, _IOFBF, 0);
	while (true)
	{
		struct	linger	sl;
		socklen_t	clen;

		/* (in)sanity check */
		if (count > cursock->instances)
		{
			errx(1, "[%s] httpd(pid %" PRIpid "): MEMORY CORRUPTION [from: `%s' req: `%s' params: `%s' vhost: '%s' referer: `%s']",
				currenttime, getpid(),
				env.remote_host ? env.remote_host : "(none)",
				orig[0] ? orig : "(none)",
				env.query_string ? env.query_string : "(none)",
				current ? current->hostname : config.system->hostname,
				referer[0] ? referer : "(none)");
		}

		setproctitle("xs(%c%d): [Reqs: %06d] Setting up myself to accept a connection",
			id, count + 1, reqs);
		filedescrs();
		setproctitle("xs(%c%d): [Reqs: %06d] Waiting for a connection...",
			id, count + 1, reqs);
		clen = salen;
		if ((csd = accept(sd, (struct sockaddr *)saddr, &clen)) < 0)
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

		dup2(csd, STDIN_FILENO);
		dup2(csd, STDOUT_FILENO);
		close(csd);

		setvbuf(stdin, NULL, _IONBF, 0);

		strlcpy(remoteaddr, "0.0.0.0", NI_MAXHOST);
#ifdef		HAVE_GETNAMEINFO
		if (!getnameinfo((struct sockaddr *)saddr, clen,
			remoteaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
		{
			/* Fake $REMOTE_ADDR because most people don't
			 * (want to) understand ::ffff: adresses.
			 */
			if (!strncmp(remoteaddr, "::ffff:", 7))
				memmove(remoteaddr, remoteaddr + 7, strlen(remoteaddr) - 7);
		}
#else		/* HAVE_GETNAMEINFO */
		{
			/* I don't need libnsl for this... */
			const in_addr_t		laddr =
				ntohl(((struct sockaddr_in *)saddr)
					->sin_addr.s_addr);
			snprintf(remoteaddr, NI_MAXHOST, "%u.%u.%u.%u",
				(laddr & 0xff000000) >> 24,
				(laddr & 0x00ff0000) >> 16,
				(laddr & 0x0000ff00) >> 8,
				(laddr & 0x000000ff));
		}
#endif		/* HAVE_GETNAMEINFO */

		strlcpy(remotehost, remoteaddr, NI_MAXHOST);
		if (config.usednslookup)
		{
			if (config.dnsattempts || config.dnstimeout)
			{
				char	buf[80];

				buf[0] = '\0';
				if (config.dnsattempts)
					snprintf(buf, sizeof(buf),
						"attempts:%u",
						config.dnsattempts);
				if (config.dnstimeout)
					snprintf(buf, sizeof(buf),
						"%s%stimeout:%u",
						buf,
						config.dnsattempts ? " " : "",
						config.dnstimeout);
				// strlcat(buf, " debug", sizeof(buf));

				setenv("RES_OPTIONS", buf, 1);
				res_init();
			}

#ifdef		HAVE_GETNAMEINFO
			getnameinfo((struct sockaddr *)saddr, clen,
				remotehost, NI_MAXHOST, NULL, 0, 0);
#else		/* HAVE_GETNAMEINFO */
# ifdef		HAVE_GETADDRINFO
			/* This is especially for broken Linux distro's
			 * that don't understand what getnameinfo() does
			 * Let's abuse getaddrinfo() instead...
			 */
			hints.ai_family = PF_INET;
			hints.ai_flags = AI_CANONNAME | AI_NUMERICHOST;
			if (!getaddrinfo(remoteaddr, NULL, &hints, &res))
			{
				strlcpy(remotehost, res->ai_canonname, NI_MAXHOST);
				freeaddrinfo(res);
			}
# else		/* HAVE_GETADDRINFO */
			/* Loooser! You will just have to use the IP-adres... */
# endif		/* HAVE_GETADDRINFO */
#endif		/* HAVE GETNAMEINFO */
#ifdef		HAVE_GETADDRINFO
			if (remotehost[0])
			{
				bool		matchreverse = false;
				struct addrinfo	*pr;

				hints.ai_family = ((struct sockaddr *)saddr)->sa_family;
				hints.ai_flags = 0;

				if (!getaddrinfo(remotehost, NULL, &hints, &res))
					/* check if hostname matches dns ip */
					for (pr = res; pr; pr = pr->ai_next)
						if (addr_equal(pr->ai_addr, (struct sockaddr *)saddr))
							matchreverse = true;
				if (!matchreverse)
					strlcpy(remotehost, remoteaddr, NI_MAXHOST);
			}
#endif		/* HAVE_GETADDRINFO */
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
		if (message503)
			secprintf("HTTP/1.1 503 Busy\r\n"
				"Content-type: text/plain\r\n"
				"Content-length: %zu\r\n\r\n%s",
				strlen(message503), message503);
		else
			do
			{
#ifdef		TCP_CORK
				if ((setsockopt(1, SOL_TCP, TCP_CORK, (int[]){1}, sizeof(int))) == -1)
					warn("setsockopt(TCP_CORK)");
#endif		/* TCP_CORK */
#ifdef		TCP_NO_PUSH
				if ((setsockopt(1, SOL_TCP, TCP_NO_PUSH, (int[]){1}, sizeof(int))) == -1)
					warn("setsockopt(TCP_NO_PUSH)");
#endif		/* TCP_NO_PUSH */
				process_request();
				alarm(10);
				if (session.chunked)
				{
					const char * const checksum = checksum_final();

					session.chunked = false;
					if (checksum)
						secprintf("0\r\nContent-MD5: %s\r\n\r\n", checksum);
					else
						secputs("0\r\n\r\n");
				}
#ifdef		TCP_CORK
				if ((setsockopt(1, SOL_TCP, TCP_CORK, (int[]){0}, sizeof(int))) == -1)
					warn("setsockopt(TCP_CORK)");
#endif		/* TCP_CORK */
#ifdef		TCP_NO_PUSH
				if ((setsockopt(1, SOL_TCP, TCP_NO_PUSH, (int[]){0}, sizeof(int))) == -1)
					warn("setsockopt(TCP_NO_PUSH)");
#endif		/* TCP_NO_PUSH */
				setproctitle("xs(%c%d): Awaiting request "
					"#%d from `%s'",
					id, count + 1, ++reqsc, remotehost);
				in_progress = false;
			}
			while (session.persistent && fflush(stdout) != EOF);
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
	memset(&env, 0, sizeof(struct env));
	*environ = NULL;
	if (session.request_headers.size)
		maplist_free(&session.request_headers);
	if (session.response_headers.size)
		maplist_free(&session.response_headers);
	memset(&session, 0, sizeof(struct session));

	setenv("SERVER_SOFTWARE", SERVER_IDENT, 1);
	setenv("SERVER_NAME", config.system->hostname, 1);
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	setenv("SERVER_PORT",
		!strcmp(cursock->port, "http") ? "80" :
		!strcmp(cursock->port, "https") ? "443" :
		cursock->port, 1);
	if (remoteaddr[0])
		setenv("REMOTE_ADDR", remoteaddr, 1);
	env.remote_addr = remoteaddr;
	if (remotehost[0])
		setenv("REMOTE_HOST", remotehost, 1);
	env.remote_host = remotehost;
	ssl_environment();
}

int
main(int argc, char **argv, char **envp)
{
	int		option;
	size_t		num;
	bool		nolog = false;
	enum		{ opt_port, opt_dir, opt_host };
	char		*longopt[] = { [2] = NULL };
	uid_t		uid = 0;
	gid_t		gid = 0;

	(void)envp;
	(void)copyright;

	if (!geteuid())
		runasroot = true;
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

	message503 = NULL;
#ifdef		PATH_PREPROCESSOR
	STRDUP(config_preprocessor, PATH_PREPROCESSOR);
#else		/* Not PATH_PREPROCESSOR */
	config_preprocessor = NULL;
#endif		/* PATH_PREPROCESSOR */
	STRDUP(config_path, HTTPD_CONF);
	while ((option = getopt(argc, argv, "a:c:d:g:m:n:p:u:NP:v")) != EOF)
	{
		switch(option)
		{
		case 'a':	/* address */
			longopt[opt_host] = optarg;
			break;
		case 'c':	/* configfile */
			FREE(config_path);
			STRDUP(config_path, optarg);
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
			STRDUP(message503, optarg);
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
			FREE(config_path);
			STRDUP(config_path, BITBUCKETNAME);
			break;
	 	case 'P':	/* preprocessor */
			if (config_preprocessor)
				FREE(config_preprocessor);
			STRDUP(config_preprocessor, optarg);
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
			printf(" OpenSSL/%u.%u.%u",
				(int)(OPENSSL_VERSION_NUMBER >> 28 & 0xf),
				(int)(OPENSSL_VERSION_NUMBER >> 20 & 0xff),
				(int)(OPENSSL_VERSION_NUMBER >> 12 & 0xff));
# if		OPENSSL_VERSION_NUMBER >> 4 & 0xff
			putchar('a' - 1 + (unsigned char)(OPENSSL_VERSION_NUMBER >> 4 & 0xff));
# endif
#endif		/* OPENSSL_VERSION_NUMBER */
			printf("\nCompiled options:\n\t"
#ifdef		HAVE_PCRE
				"+PCRE "
#else		/* HAVE_PCRE */
				"-PCRE "
#endif		/* HAVE_PCRE */
#ifdef		HAVE_CURL
				"+CURL "
#else		/* HAVE_CURL */
				"-CURL "
#endif		/* HAVE_CURL */
#ifdef	 	HAVE_DB_H
				"+BDB "
#else	 	/* HAVE_DB_H */
				"-BDB "
#endif	 	/* HAVE_DB_H */
#ifdef		HAVE_SSP
				"+SSP "
#else		/* HAVE_SSP */
				"-SSP "
#endif		/* HAVE_SSP */
#ifdef	 	 HANDLE_SSL_TLSEXT
  				"+TLSEXT "
#else		 /* HANDLE_SSL_TLSEXT */
  				"-TLSEXT "
#endif		 /* HANDLE_SSL_TLSEXT */
				);
			printf("\nAvailable modules:\n\t");
			const char * const *mods = module_names;
			for (const char *mod; (mod = *mods); mods++)
				printf("%s ", mod);
			printf("\nConfiguration file:\n"
#ifdef		PATH_PREPROCESSOR
				"\t%s %s\n", config_preprocessor, config_path
#else		/* PATH_PREPROCESSOR */
				"\t%s\n", config_path
#endif		/* PATH_PREPROCESSOR */
				);
			return 0;
		default:
			errx(1,
	"Usage: httpd [-c configfile] [-P preprocessor] [-d rootdir]\n"
	"\t[-u username] [-g group] [-p port] [-a address] [-n number]\n"
	"\t[-m service-message] [-N] [-v]");
		}
	}
	load_config();

#ifdef		HAVE_SETPRIORITY
	if (setpriority(PRIO_PROCESS, (pid_t)0, config.priority))
		warn("setpriority()");
#endif		/* HAVE_SETPRIORITY */

	/* Explicity set these, overriding default or implicit setting */
#define	SET_OPTION(option, config) \
	if (longopt[option]) { \
		if (config) \
			FREE(config); \
		STRDUP(config, longopt[option]); \
	}

	if (nolog)
	{
		STRDUP(config.pidfile, BITBUCKETNAME);
		STRDUP(config.system->logaccess, BITBUCKETNAME);
		STRDUP(config.system->logreferer, BITBUCKETNAME);
		STRDUP(config.system->logerror, BITBUCKETNAME);
		config.system->logscript = NULL;
	}
	if (config.sockets)
		SET_OPTION(opt_port,  config.sockets[0].port);
	SET_OPTION(opt_dir,  config.system->htmldir);
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
	MALLOC(environ, char *, 1);
	*environ = NULL;

	standalone_main();
}
