/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#ifdef		HAVE_SYS_RESOURCE_H
#include	<sys/resource.h>
#endif		/* HAVE_SYS_RESOURCE_H */
#include	<fcntl.h>
#include	<sys/signal.h>
#include	<sys/stat.h>
#include	<sys/wait.h>

#include	<stdio.h>
#include	<stdbool.h>
#include	<errno.h>
#include	<time.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<pwd.h>
#include	<grp.h>
#include	<unistd.h>
#include	<string.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<ctype.h>
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */
#include	<stdarg.h>
#include	<poll.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"ssi.h"
#include	"ssl.h"
#include	"cgi.h"
#include	"fcgi.h"
#include	"hash.h"
#include	"extra.h"
#include	"malloc.h"
#include	"modules.h"
#include	"convert.h"

static	void		time_is_up(int)	NORETURN;
static	bool		append(char **, bool, const char * const format, ...)	PRINTF_LIKE(3,4);

static pid_t			child;


static	void
time_is_up(int sig)
{
	if (child != (pid_t)-1)
	{
		(void) killpg(child, SIGTERM);
		(void) killpg(child, SIGKILL);
	}
	alarm_handler(sig);
	exit(1);
}

static	bool
append(char **buffer, bool prepend, const char * const format, ...)
{
	va_list		ap;
	size_t		slen, llen;
	char		*newbuf = NULL;
	char		empty_string[] = "";

	va_start(ap, format);
	llen = vsnprintf(empty_string, 0, format, ap);
	va_end(ap);
	if (!llen || !buffer)
		return false;

	if (!*buffer)
	{
		MALLOC(newbuf, char, llen + 1);
		newbuf[0] = '\0';
		va_start(ap, format);
		vsnprintf(newbuf, llen + 1, format, ap);
		va_end(ap);
		*buffer = newbuf;
		return true;
	}

	slen = strlen(*buffer);
	REALLOC(*buffer, char, slen + llen + 1);
	newbuf = *buffer;

	va_start(ap, format);
	if (prepend)
	{
		const char	ch = newbuf[0];

		memmove(newbuf + llen, newbuf, slen + 1);
		newbuf[0] = '\0';
		vsnprintf(newbuf, llen + 1, format, ap);
		newbuf[llen] = ch;
	}
	else
	{
		newbuf += slen;
		vsnprintf(newbuf, llen + 1, format, ap);
	}

	va_end(ap);
	return true;
}

void
do_script(const char *path, const char *base, const char *file, const char *engine)
{
	off_t		totalwritten;
	char		fullpath[XS_PATH_MAX], input[RWBUFSIZE],
			line[LINEBUFSIZE];
	const char	*argv1;
	int		p[2], r[2];
	bool		nph, dossi;
	FILE		*logfile;
	int		q[2];
	bool		ssl_post = false;
	struct	sigaction	action, ignore;

	child = (pid_t)-1;
#ifdef		HAVE_SIGEMPTYSET
	sigemptyset(&action.sa_mask);
	sigemptyset(&ignore.sa_mask);
#else		/* Not HAVE_SIGEMPYSET */
	action.sa_mask = 0;
	ignore.sa_mask = 0;
#endif		/* HAVE_SIGEMPTYSET */
	action.sa_handler = time_is_up;
	action.sa_flags = 0;
	ignore.sa_handler = SIG_IGN;
	ignore.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);

	(void)alarm(60 * config.scripttimeout);
	fflush(stdout);
	unsetenv("REDIRECT_STATUS");

	/* snip++ */

	snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);

	if (!engine)
	{
		struct	stat		statbuf;

		if (!stat(fullpath, &statbuf) && !(statbuf.st_mode & S_IXUSR))
		{
			server_error(403, "File permissions deny access",
				"NOT_AVAILABLE");
			return;
		}
	}

	if (env.request_uri)
		setenv("DOCUMENT_ROOT", getdocroot(env.request_uri), 1);
	setenv("SCRIPT_FILENAME", fullpath, 1);
	setenv("REDIRECT_STATUS", "200", 1);

	nph = (!strncmp(file, "nph-", 4) || strstr(file, "/nph-"));
	if (config.usessi)
		dossi = (!strncmp(file, "ssi-", 4) || strstr(file, "/ssi-"));
	else
		dossi = false;

	p[0] = p[1] = -1;
	q[0] = q[1] = -1;
	r[0] = r[1] = -1;

#define	CLOSEFD	do { \
		if (p[0] >= 0) close(p[0]); \
		if (p[1] >= 0) close(p[1]); \
		if (r[0] >= 0) close(r[0]); \
		if (r[1] >= 0) close(r[1]); \
		if (q[0] >= 0) close(q[0]); \
		if (q[1] >= 0) close(q[1]); \
	} while(0)

	if (1 /* !nph || do_ssl */)
	{
		if (pipe(p))
		{
			xserror(500, "pipe(): %s", strerror(errno));
			return;
		}
	}

	ssl_post = session.postonly;
	if (ssl_post)
	{
		const char * const	expect = getenv("HTTP_EXPECT");

		if (pipe(q))
		{
			xserror(500, "pipe(): %s", strerror(errno));
			CLOSEFD;
			return;
		}
		if (expect && strcasestr(expect, "100-continue"))
			secprintf("%s 100 Continue\r\n\r\n",
				env.server_protocol);
		else if (expect)
		{
			xserror(417, "Expectation failed");
			CLOSEFD;
			return;
		}
	}

	logfile = current->openscript
		? current->openscript
		: config.system->openscript;

	if (logfile)
	{
		if (pipe(r) < 0)
		{
			xserror(500, "pipe(): %s", strerror(errno));
			CLOSEFD;
			return;
		}
	}
	else
	{
		r[0] = -1;
		r[1] = open(BITBUCKETNAME, O_WRONLY);
		if (r[1] < 0)
		{
			xserror(500, "open(): %s", strerror(errno));
			CLOSEFD;
			return;
		}
	}

	/* Special case: don't fork */
	if (engine && !strcmp(engine, "internal:fcgi") &&
		current->fcgisocket)
	{
		logfile = NULL;
		if (run_fcgi(q[0], p[1], r[1]) < 0)
		{
			xserror(500, "run_fcgi()");
			CLOSEFD;
			return;
		}
		if (ssl_post)
			close(q[0]);
		close(p[1]);
		close(r[1]);
		q[0] = p[1] = r[1] = -1;
	}
	else

	sigaction(SIGCHLD, &ignore, &action);
	switch (child = fork())
	{
	case -1:
		xserror(500, "fork(): %s", strerror(errno));
		CLOSEFD;
		return;
	case 0:
#ifdef		HAVE_SETRLIMIT
		{
			struct	rlimit		limits;
#ifdef		RLIMIT_CPU
			limits.rlim_cur = 60 * (rlim_t)config.scriptcpulimit;
			limits.rlim_max = 10 + limits.rlim_cur;
			setrlimit(RLIMIT_CPU, &limits);
#endif		/* RLIMIT_CPU */
#ifdef		RLIMIT_CORE
			limits.rlim_cur = limits.rlim_max = 0;
			setrlimit(RLIMIT_CORE, &limits);
#endif		/* RLIMIT_CORE */
		}
#endif		/* HAVE_SETRLIMIT */

		dup2(p[1], STDOUT_FILENO);
		dup2(r[1], STDERR_FILENO);

		/* Posting via SSL takes a lot of extra work */
		if (ssl_post)
			dup2(q[0], STDIN_FILENO);

#ifdef		HAVE_SETSID
		if (setsid() == -1)
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[setsid() failed]\n");
			exit(1);
		}
#else		/* Not HAVE_SETSID */
		if (setpgrp(getpid(), 0) == -1)
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[setpgrp() failed]\n");
			exit(1);
		}
#endif		/* HAVE_SETSID */

		closefrom(3);
		/* euid should be set, now fix uid */
		if (!origeuid)
		{
			/* euid is not set on very early error cgi: fallback */
			setuid(geteuid() ? geteuid() : config.system->userid);
			setgid(getegid() ? getegid() : config.system->groupid);
		}
		if (!geteuid())
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[Invalid euid setting]\n");
			exit(1);
		}
		setenv("PATH", config.scriptpath, 1);
		if (chdir(base))
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[Cannot change directory]\n");
			exit(1);
		}

		if (config.usescriptargs &&
				env.query_string &&
				!strchr(env.query_string, '='))
			/* Mandated by CGI/1.1 standard: pass GET parameters
			 * as cmdline options/arguments if there is no '='.
			 * May trigger undesired behaviour in interpreters
			 * (e.g. passing -s to output the source in PHP)
			 */
			argv1 = env.query_string;
		else
			argv1 = NULL;

#ifdef		HAVE_SETPRIORITY
		if (setpriority(PRIO_PROCESS, (pid_t)0, config.scriptpriority))
			warn("setpriority()");
#endif		/* HAVE_SETPRIORITY */

		/* interpreter modules */
		if (engine)
			for (struct module *mod, **mods = modules;
					(mod = *mods); mods++)
				if (mod->engine && !strcmp(engine, mod->engine))
				{
					int	fd;
					
					if ((fd = open(fullpath, O_RDONLY)) < 0)
					{
						secprintf("Content-type: text/plain\r\n\r\n");
						secprintf("[Cannot change directory]\n");
						exit(1);
					}
					mod->file_handler(fullpath, fd, STDOUT_FILENO);
					exit(0);
				}

		if (engine)
		{
			const char	meta[] = " \t&();<>|{}$%";

			if (!strncmp(engine, "internal:", 9))
			{
				secprintf("Content-type: text/plain\r\n\r\n");
				secprintf("[Interpreter not available]\n");
				exit(1);
			}

			/* let shell handle engines containing metacharacters */
			if (engine[strcspn(engine, meta)])
			{
				unsigned int	len, pos;
				char		*buffer;
				const char	*pengine;

				len = 2 + strlen(engine) + strlen(fullpath);
				MALLOC(buffer, char, len);
				/* optional %f indicates filename */
				if ((pengine = strstr(engine, "%f")))
				{
					pos = pengine - engine;
					snprintf(buffer, len, "%*.*s%s%s", pos, pos,
						engine, fullpath, pengine + 2);
				}
				else
					snprintf(buffer, len, "%s %s", engine, fullpath);
				(void) execl("/bin/sh", "sh", "-c", buffer, NULL);
				FREE(buffer);
			}
			else
				(void) execl(engine, engine, fullpath, argv1, NULL);
		}
		else
			(void) execl(fullpath, file, argv1, NULL);
		/* print error */
		fprintf(stderr, "execl(`%s') failed: %s\n",
			engine ? engine : fullpath, strerror(errno));
		close(STDERR_FILENO);
		/* no need to give local path info to the visitor */
		xserror(500, "execl(): %s", strerror(errno));
		exit(1);
	default:
		if (ssl_post)
			close(q[0]);
		close(p[1]);
		close(r[1]);
		q[0] = p[1] = r[1] = -1;
		break;
	}

	/* DECL */
	const char * const te = getenv("HTTP_TRANSFER_ENCODING");
	if (ssl_post && te && !strcasecmp(te, "chunked"))
	{
		char		buffer[20];
		const size_t	buflen = sizeof buffer;
		char		*cbuf = NULL;
		size_t		chunksz;

		while (1)
		{
			if (readline(0, buffer, buflen) != ERR_NONE)
			{
				if (cbuf)
					FREE(cbuf);
				CLOSEFD;
				return;
			}
			buffer[buflen-1] = '\0';

			chunksz = (size_t)strtoul(buffer, NULL, 16);
			if (!chunksz)
			{
				/* end of data marker */
				/* now read \r\n */
				secread(0, buffer, 2);
				break;
			}
			/* two bytes extra for trailing \r\n */
			REALLOC(cbuf, char, chunksz + 2);
			if (!cbuf || (secread(0, cbuf, chunksz + 2) < 0))
			{
				CLOSEFD;
				return;
			}

			if ((write(q[1], cbuf, chunksz) < 0) &&
				(errno != EINTR))
			{
				xserror(500, "Connection closed - %zu bytes not written",
					 chunksz);
				CLOSEFD;
				return;
			}
		}

		if (cbuf)
			FREE(cbuf);
		session.postread = true;
		close(q[1]);
		q[1] = -1;
	}
	else if (ssl_post)
	{
		off_t		writetodo;

		writetodo = env.content_length;
		while (writetodo > 0)
		{
			char		inbuf[RWBUFSIZE];
			ssize_t		result;
			size_t		offset, tobewritten;
			struct pollfd	pfd = { q[1], POLLWRNORM, 0 };

			if (writetodo > RWBUFSIZE)
				tobewritten = RWBUFSIZE;
			else
				tobewritten = (size_t)writetodo;
			result = secread(0, inbuf, tobewritten);
			if (result < 0)
			{
				CLOSEFD;
				return;
			}
			else if (!result)
				break;
			tobewritten = result;
			offset = 0;

			result = poll(&pfd, 1, 0);
			if (result < 0 || pfd.revents & (POLLERR | POLLHUP))
				/* Cannot write - remote end closed? */
				break;
			while ((result = write(q[1], inbuf + offset, tobewritten - offset)) < (int)(tobewritten - offset))
			{
				if ((result < 0) && (errno != EINTR))
				{
					xserror(500, "Connection closed - %" PRIoff
						" of %zu bytes not written",
						writetodo, tobewritten);
					CLOSEFD;
					return;
				}
				else if (result > 0)
					offset += result;
			}
			writetodo -= tobewritten;
		}

		session.postread = true;
		close(q[1]);
		q[1] = -1;
	}

	if (logfile)
	{
		int	printerr = 0;

		switch(fork())
		{
		case -1:
			warn("fork(errlogger)");
			break;
		case 0:
			/* handle stderr */
			close(p[0]);
			initreadmode(true);
			while (true)
			{
				if (readline(r[0], line, sizeof(line)) != ERR_NONE)
					break;

				if (!printerr)
				{
					fprintf(logfile, "%% [%s] %s %s %s\n%% 200 %s\n"
						"%%stderr\n",
						currenttime,
						env.request_method,
						env.request_uri,
						env.server_protocol,
						fullpath);
					printerr = 1;
				}
				if ('%' == line[0])
					fprintf(logfile, "%% %s\n", line);
				else
					fprintf(logfile, "%s\n", line);
			}
			exit(0);
		default:
			close(r[0]);
			r[0] = -1;
		}
	}

	initreadmode(true);
	if (!nph)
	{
		char		*head = NULL;
		struct maplist	http_headers;
		bool		ctype, status, lastmod, server, pragma;

		ctype = status = lastmod = server = pragma = false;
		if (readheaders(p[0], &http_headers) < 0)
		{
			/* Script header read error */
			if (logfile)
			{
				fprintf(logfile, "%% [%s] %s %s %s\n%% 503 %s\n",
					currenttime,
					env.request_method,
					env.request_uri,
					env.server_protocol,
					fullpath);
				fprintf(logfile, "%%%%error\n"
					"503 Script did not end header\n");
			}
			xserror(503, "Script did not end header");
			CLOSEFD;
			return;
		}
		for (size_t sz = 0; sz < http_headers.size; sz++)
		{
			const char * const idx = http_headers.elements[sz].index;
			const char * const val = http_headers.elements[sz].value;

			/* Look for status header */
			if (!status)
			{
				if (!strcasecmp(idx, "Status"))
				{
					status = true;
					session.rstatus = strtoul(val, NULL, 10);
					append(&head, true, "%s %s\r\n",
						env.server_protocol, val);
					continue;
				}
				else if (!strcasecmp(idx, "Location"))
				{
					status = true;
					session.rstatus = 302;
					append(&head, true, "%s 302 Moved\r\n",
						env.server_protocol);
				}
			}

			if (!strcasecmp(idx, "Location"))
			{
				if (!val || !*val)
					/* skip */;
				else if ('/' == val[0])
				{
					if (!strcmp(cursock->port, "http"))
						append(&head, false, "Location: http://%s%s\r\n",
							current->hostname, val);
					else if (cursock->usessl && !strcmp(cursock->port, "https"))
						append(&head, false, "Location: https://%s%s\r\n",
							current->hostname, val);
					else if (cursock->usessl)
						append(&head, false, "Location: https://%s:%s%s\r\n",
							current->hostname, cursock->port, val);
					else
						append(&head, false, "Location: http://%s:%s%s\r\n",
							current->hostname, cursock->port, val);
				}
				else
					append(&head, false, "Location: %s\r\n", val);
			}
			else if (!strcasecmp(idx, "Content-type"))
			{
				ctype = true;
				append(&head, false, "Content-type: %s\r\n", val);
			}
			else if (!strcasecmp(idx, "Last-modified"))
			{
				append(&head, false, "Last-modified: %s\r\n", val);
				lastmod = true;
			}
			else if (!strcasecmp(idx, "Cache-control"))
			{
				if (session.httpversion >= 11)
					append(&head, false, "Cache-control: %s\r\n", val);
				else if (!pragma)
					append(&head, false, "Pragma: no-cache\r\n");
				pragma = true;
			}
			else if (!strcasecmp(idx, "Pragma"))
			{
				if (session.httpversion < 11 && !pragma)
					append(&head, false, "Pragma: %s\r\n", val);
				pragma = true;
			}
			else if (!strcasecmp(idx, "Server"))
			{
				/* Append value to SERVER_IDENT */
				if (!strncasecmp(val, SERVER_IDENT, strlen(SERVER_IDENT)))
					append(&head, false, "Server: %s\r\n", val);
				else
					append(&head, false, "Server: %s %s\r\n", config.serverident, val);
				server = true;
			}
			else if (!strcasecmp(idx, "Date"))
			{
				/* Thank you, I do know how to tell time */
			}
			else
				append(&head, false, "%s: %s\r\n", idx, val);
		}
		if (session.headers)
		{
			if (!status)
				append(&head, true, "%s 200 OK\r\n",
					env.server_protocol);
			if (!ctype)
				append(&head, false, "Content-type: text/html\r\n");
			if (!lastmod)
				append(&head, false, "Last-modified: %s\r\n",
					currenttime);
			if (!server)
				append(&head, false, "Server: %s\r\n", config.serverident);
			if (session.httpversion >= 11)
				append(&head, false, "Transfer-encoding: chunked\r\n");
			if (config.usecontentmd5 && session.trailers)
				append(&head, false, "Trailer: Content-MD5\r\n");
			if (session.httpversion >= 11)
				append(&head, false, "Connection: close\r\n");
			append(&head, false, "Date: %s\r\n", currenttime);
			secprintf("%s\r\n", head);
			if (head)
				FREE(head);
			/* 304 pages don't even get an empty body */
			if (session.rstatus != 204 && session.rstatus != 304 &&
					session.httpversion >= 11)
				session.chunked = true;
			if (config.usecontentmd5 && session.trailers)
				checksum_init();
		}
		maplist_free(&http_headers);
	}
	else /* nph */
	{
		for (;;)
		{
			if (readline(p[0], line, sizeof(line)) != ERR_NONE)
			{
				xserror(503, "Script did not end header");
				CLOSEFD;
				return;
			}
			if (session.headers)
				secputs(line);
			if (!line[0])
				break;
		}
	}
	fflush(stdout);

	if (session.headonly)
		goto END;

	totalwritten = 0;
	if (dossi)
	{
		off_t		ttw = 0;
		/* Parse the output of CGI script for SSI directives */
		sendwithdirectives(p[0], &ttw);
		totalwritten = ttw;
	}
	else
	{
		ssize_t		result;

		while ((result = secread(p[0], input, RWBUFSIZE)) > 0)
		{
			off_t		writetodo = result;
			const char	*temp = input;

			while (writetodo > 0)
			{
				const ssize_t	written = \
					secwrite(temp, writetodo);

				if (written < 0)
				{
					secprintf("[Connection closed - %" PRIoff " bytes not written]\n",
						writetodo);
					CLOSEFD;
					return;
				}
				else if (!written)
				{
					secprintf("[Connection closed: couldn't write]\n");
					CLOSEFD;
					return;
				}
				else
				{
					writetodo -= written;
					temp += written;
				}
			}
			totalwritten += result;
		}
	}

#undef	CLOSEFD

	if (!getenv("ERROR_CODE"))
	{
		char	*request;

		if (env.query_string)
			ASPRINTF(&request, "%s%s?%s", path,
				env.path_info ? env.path_info : "",
				env.query_string);
		else
			ASPRINTF(&request, "%s%s", path,
				env.path_info ? env.path_info : "");
		logrequest(request, totalwritten);
		FREE(request);
	}
	END:
	fflush(stdout);
	close(p[0]);
	if (child > 0)
	{
		int	chldstat;
		waitpid(child, &chldstat, 0);
	}
	sigaction(SIGCHLD, &action, NULL);
}
