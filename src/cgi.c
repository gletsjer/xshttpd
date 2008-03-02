/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

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
#ifdef		HAVE_PERL
#include	<EXTERN.h>
#include	<perl.h>
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
#include	<python2.5/Python.h>
#endif		/* HAVE_PYTHON */

#include	"httpd.h"
#include	"ssi.h"
#include	"ssl.h"
#include	"cgi.h"
#include	"fcgi.h"
#include	"htconfig.h"
#include	"extra.h"
#include	"malloc.h"

static	void		time_is_up(int)	NORETURN;
static	bool		append(char **, bool, const char * const format, ...)	PRINTF_LIKE(3,4);

#ifdef		HAVE_PERL
char *	perlargs[] = { NULL, NULL };
extern	PerlInterpreter *my_perl;
#endif		/* HAVE_PERL */

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
	char		*line, *newbuf;
	size_t		slen, llen;

	line = NULL;
	va_start(ap, format);
	llen = vasprintf(&line, format, ap);
	va_end(ap);
	if (!line)
		return false;

	if (!buffer || !*buffer)
	{
		*buffer = line;
		return true;
	}

	slen = strlen(*buffer);
	REALLOC(*buffer, char, slen + llen + 1);
	newbuf = *buffer;

	if (prepend)
	{
		memmove(newbuf + llen, newbuf, slen + 1);
		memmove(newbuf, line, llen);
	}
	else
		memmove(newbuf + slen, line, llen + 1);

	free(line);
	return true;
}

void
do_script(const char *path, const char *base, const char *file, const char *engine)
{
	off_t		totalwritten;
	char		fullpath[XS_PATH_MAX], input[RWBUFSIZE],
			line[LINEBUFSIZE];
	char		*argv1;
	int		p[2], r[2], chldstat;
	bool		nph, dossi;
	unsigned int	left;
	FILE		*logfile;
#ifdef		HANDLE_SSL
	int		q[2];
	bool		ssl_post = false;
#endif		/* HANDLE_SSL */
	struct	sigaction	action;

	child = (pid_t)-1;
#ifdef		HAVE_SIGEMPTYSET
	sigemptyset(&action.sa_mask);
#else		/* Not HAVE_SIGEMPYSET */
	action.sa_mask = 0;
#endif		/* HAVE_SIGEMPTYSET */
	action.sa_handler = time_is_up;
	action.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);

	left = alarm(60 * config.scripttimeout); fflush(stdout);
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

	setenv("SCRIPT_FILENAME", fullpath, 1);
	setenv("REDIRECT_STATUS", "200", 1);

	nph = (!strncmp(file, "nph-", 4) || strstr(file, "/nph-"));
	if (config.usessi)
		dossi = (!strncmp(file, "ssi-", 4) || strstr(file, "/ssi-"));
	else
		dossi = false;
	p[0] = p[1] = -1;
	if (1 /* !nph || do_ssl */)
	{
		if (pipe(p))
		{
			xserror(500, "pipe(): %s", strerror(errno));
			goto END;
		}
	}

#ifdef		HANDLE_SSL
	q[0] = q[1] = -1;
	ssl_post = postonly;
	if (ssl_post)
	{
		char	*expect = getenv("HTTP_EXPECT");

		if (pipe(q))
		{
			xserror(500, "pipe(): %s", strerror(errno));
			goto END;
		}
		if (expect && strcasestr(expect, "100-continue"))
			secprintf("%s 100 Continue\r\n\r\n", httpver);
		else if (expect)
		{
			xserror(417, "Expectation failed");
			goto END;
		}
	}
#endif		/* HANDLE_SSL */

	r[0] = r[1] = -1;
	if (pipe(r))
	{
		xserror(500, "pipe(): %s", strerror(errno));
		goto END;
	}

	logfile = current->openscript
		? current->openscript
		: config.system->openscript;

	/* Special case: don't fork */
	if (engine && !strcmp(engine, "internal:fcgi") &&
		current->fcgisocket)
	{
		logfile = NULL;
		if (run_fcgi(q[0], p[1], r[1]) < 0)
		{
			xserror(500, "run_fcgi()");
			goto END;
		}
		if (ssl_post)
			close(q[0]);
		close(p[1]);
		close(r[1]);
	}
	else

	switch (child = fork())
	{
	case -1:
		xserror(500, "fork(): %s", strerror(errno));
		goto END;
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

		dup2(p[1], 1);
		dup2(r[1], 2);

#ifdef		HANDLE_SSL
		/* Posting via SSL takes a lot of extra work */
		if (ssl_post)
			dup2(q[0], 0);
#endif		/* HANDLE_SSL */

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
		argv1 = getenv("QUERY_STRING");
		if (argv1 && strchr(argv1, '='))
			argv1 = NULL;

#ifdef		HAVE_SETPRIORITY
		if (setpriority(PRIO_PROCESS, (pid_t)0, config.scriptpriority))
			warn("setpriority()");
#endif		/* HAVE_SETPRIORITY */

#ifdef		HAVE_PERL
		if (engine && !strcmp(engine, "internal:perl"))
		{
			perlargs[0] = fullpath;
			perl_call_argv("Embed::Persistent::eval_file",
				G_DISCARD | G_EVAL, perlargs);
			exit(0);
		}
		else
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
		if (engine && !strcmp(engine, "internal:python"))
		{
			FILE	*fp = fopen(fullpath, "r");
			PyRun_SimpleFile(fp, fullpath);
			fclose(fp);
			exit(0);
		}
		else
#endif		/* HAVE_PERL */
		if (engine)
		{
			const char	meta[] = " \t&();<>|{}$%";

			/* let shell handle engines containing metacharacters */
			if (engine[strcspn(engine, meta)])
			{
				unsigned int	len, pos;
				char		*buffer, *pengine;

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
				free(buffer);
			}
			else
				(void) execl(engine, engine, fullpath, argv1, NULL);
		}
		else
			(void) execl(fullpath, file, argv1, NULL);
		/* print error */
		fprintf(stderr, "execl(`%s') failed: %s\n",
			engine ? engine : fullpath, strerror(errno));
		close(2);
		/* no need to give local path info to the visitor */
		xserror(500, "execl(): %s", strerror(errno));
		exit(1);
	default:
		close(p[1]);
		close(r[1]);
#ifdef		HANDLE_SSL
		if (ssl_post)
			close(q[0]);
#endif		/* HANDLE_SSL */
		break;
	}

#ifdef		HANDLE_SSL
	const char * const te = getenv("HTTP_TRANSFER_ENCODING");
	if (ssl_post && te && !strcasecmp(te, "chunked"))
	{
		char		buffer[20];
		const size_t	buflen = sizeof buffer;
		char		*cbuf = NULL;

		while (1)
		{
			if (readline(0, buffer, buflen) != ERR_NONE)
			{
				if (cbuf)
					free(cbuf);
				goto END;
			}
			buffer[buflen-1] = '\0';

			const size_t chunksz = (size_t)strtoul(buffer, NULL,16);
			if (!chunksz)
			{
				/* end of data marker */
				/* now read \r\n */
				secread(0, buffer, 2);
				break;
			}
			/* two bytes extra for trailing \r\n */
			REALLOC(cbuf, char, chunksz + 2);
			if (!cbuf)
				goto END;
			if (secread(0, cbuf, chunksz + 2) < 0)
				goto END;

			if ((write(q[1], cbuf, chunksz) < 0) &&
				(errno != EINTR))
			{
				xserror(500, "Connection closed (fd = %d, todo = %zu",
					q[1], chunksz);
				goto END;
			}
		}

		if (cbuf)
			free(cbuf);
		postread = true;
		close(q[1]);
	}
	else if (ssl_post)
	{
		unsigned long		writetodo;

		writetodo = strtoul(getenv("CONTENT_LENGTH"), NULL, 10);
		while (writetodo > 0)
		{
			char	inbuf[RWBUFSIZE];
			int	offset, result;
			size_t	tobewritten;

			tobewritten = writetodo > RWBUFSIZE ? RWBUFSIZE : writetodo;
			result = secread(0, inbuf, tobewritten);
			if (result < 0)
				goto END;
			else if (!result)
				break;
			tobewritten = result;
			offset = 0;
			while ((result = write(q[1], inbuf + offset, tobewritten - offset)) < (int)(tobewritten - offset))
			{
				if ((result < 0) && (errno != EINTR))
				{
					xserror(500, "Connection closed (fd = %d, todo = %ld",
						q[1], writetodo);
					goto END;
				}
				else if (result > 0)
					offset += result;
			}
			writetodo -= tobewritten;
		}

		postread = true;
		close(q[1]);
	}
#endif		/* HANDLE_SSL */

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
			initreadmode(true);
			while (true)
			{
				if (readline(r[0], line, sizeof(line)) != ERR_NONE)
					break;

				if (!printerr)
				{
					setcurrenttime();
					fprintf(logfile, "%% [%s] %s %s %s\n%% 200 %s\n"
						"%%stderr\n",
						currenttime,
						getenv("REQUEST_METHOD"),
						getenv("REQUEST_URI"),
						getenv("SERVER_PROTOCOL"),
						fullpath);
					printerr = 1;
				}
				if ('%' == line[0])
					fprintf(logfile, "%% %s\n", line);
				else
					fprintf(logfile, "%s\n", line);
			}
			exit(0);
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
				setcurrenttime();
				fprintf(logfile, "%% [%s] %s %s %s\n%% 503 %s\n",
					currenttime,
					getenv("REQUEST_METHOD"),
					getenv("REQUEST_URI"),
					getenv("SERVER_PROTOCOL"),
					fullpath);
				fprintf(logfile, "%%%%error\n"
					"503 Script did not end header\n");
			}
			xserror(503, "Script did not end header");
			goto END;
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
					rstatus = atoi(val);
					append(&head, true, "%s %s\r\n", httpver, val);
					continue;
				}
				else if (!strcasecmp(idx, "Location"))
				{
					status = true;
					rstatus = 302;
					append(&head, true, "%s 302 Moved\r\n", httpver);
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
				if (headers >= 11)
					append(&head, false, "Cache-control: %s\r\n", val);
				else if (!pragma)
					append(&head, false, "Pragma: no-cache\r\n");
				pragma = true;
			}
			else if (!strcasecmp(idx, "Pragma"))
			{
				if (headers < 11 && !pragma)
					append(&head, false, "Pragma: %s\r\n", val);
				pragma = true;
			}
			else if (!strcasecmp(idx, "Server"))
			{
				/* Append value to SERVER_IDENT */
				if (!strncasecmp(val, SERVER_IDENT, strlen(SERVER_IDENT)))
					append(&head, false, "Server: %s\r\n", val);
				else
					append(&head, false, "Server: %s %s\r\n", SERVER_IDENT, val);
				server = true;
			}
			else if (!strcasecmp(idx, "Date"))
			{
				/* Thank you, I do know how to tell time */
			}
			else
				append(&head, false, "%s: %s\r\n", idx, val);
		}
		if (headers >= 10)
		{
			if (!status)
				append(&head, true, "%s 200 OK\r\n", httpver);
			if (!ctype)
				append(&head, false, "Content-type: text/html\r\n");
			setcurrenttime();
			if (!lastmod)
				append(&head, false, "Last-modified: %s\r\n",
					currenttime);
			if (!server)
				append(&head, false, "Server: %s\r\n", SERVER_IDENT);
			if (headers >= 11)
				append(&head, false, "Transfer-encoding: chunked\r\n");
			append(&head, false, "Date: %s\r\n", currenttime);
			secprintf("%s\r\n", head);
			if (head)
				free(head);
			/* 304 pages don't even get an empty body */
			if (rstatus != 204 && rstatus != 304 && headers >= 11)
				chunked = true;
		}
		freeheaders(&http_headers);
	}
	else /* nph */
	{
		for (;;)
		{
			if (readline(p[0], line, sizeof(line)) != ERR_NONE)
			{
				xserror(503, "Script did not end header");
				goto END;
			}
			if (headers >= 10)
				secputs(line);
			if (!line[0])
				break;
		}
	}
	fflush(stdout);

	if (headonly)
		goto END;

	totalwritten = 0;
	if (dossi)
	{
		off_t ttw = 0;
		/* Parse the output of CGI script for SSI directives */
		sendwithdirectives(p[0], &ttw);
		totalwritten = ttw;
	}
	else
	{
		int	result;

		while ((result = secread(p[0], input, RWBUFSIZE)) > 0)
		{
			unsigned long	writetodo = result;
			char		*temp = input;

			while (writetodo > 0)
			{
				const ssize_t	written = \
					secwrite(temp, writetodo);

				if (written < 0)
				{
					secprintf("[Connection closed: %s (fd = %d, temp = %p, todo = %ld]\n",
						strerror(errno), fileno(stdout), temp,
						writetodo);
					goto END;
				}
				else if (!written)
				{
					secprintf("[Connection closed: couldn't write]\n");
					goto END;
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

	if (!getenv("ERROR_CODE"))
	{
		char	*request, *qs, *pi;

		pi = getenv("PATH_INFO");
		if ((qs = getenv("QUERY_STRING")))
			asprintf(&request, "%s%s?%s", path, pi ? pi : "", qs);
		else
			asprintf(&request, "%s%s", path, pi ? pi : "");
		logrequest(request, totalwritten);
		free(request);
	}
	END:
	fflush(stdout); close(p[0]); close(p[1]);
	fflush(stderr); close(r[0]); close(r[1]);
#ifdef		HANDLE_SSL
	if (ssl_post)
	{
		close(q[0]); close(q[1]);
	}
#endif		/* HANDLE_SSL */
#ifdef		HAVE_SIGEMPTYSET
	sigemptyset(&action.sa_mask);
#else		/* Not HAVE_SIGEMPYSET */
	action.sa_mask = 0;
#endif		/* HAVE_SIGEMPTYSET */
	action.sa_handler = alarm_handler;
	action.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);
	alarm(left);
	if (child > 0)
		waitpid(child, &chldstat, 0);
}
