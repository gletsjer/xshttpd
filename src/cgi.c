/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: cgi.c,v 1.138 2007/04/07 21:34:50 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */
#ifdef		HAVE_SYS_RESOURCE_H
#include	<sys/resource.h>
#endif		/* HAVE_SYS_RESOURCE_H */
#include	<fcntl.h>
#include	<sys/signal.h>
#include	<sys/stat.h>
#include	<sys/wait.h>

#include	<stdio.h>
#include	<errno.h>
#ifdef		HAVE_TIME_H
#ifdef		TIME_WITH_SYS_TIME
#include	<time.h>
#endif		/* TIME_WITH_SYS_TIME */
#endif		/* HAVE_TIME_H */
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
#include	"htconfig.h"
#include	"extra.h"

static	const	char	*skipspaces(const char *);
static	void		time_is_up(int)	NORETURN;
static	int		append(char *, int, const char *format, ...)	PRINTF_LIKE(3,4);

#ifdef		HAVE_PERL
char *	perlargs[] = { NULL, NULL };
extern	PerlInterpreter *my_perl;
#endif		/* HAVE_PERL */

static pid_t			child;


static const char *
skipspaces(const char *string)
{
	while ((*string == ' ') || (*string == '\t'))
		string++;
	return(string);
}

static	void
time_is_up(int sig)
{
	if (child != (pid_t)-1)
	{
		(void) killpg(child, SIGTERM);
		(void) mysleep(1);
		(void) killpg(child, SIGKILL);
	}
	alarm_handler(sig);
	exit(1);
}

static	int
append(char *buffer, int prepend, const char *format, ...)
{
	va_list	ap;
	char	line[HEADSIZE];

	va_start(ap, format);
	vsnprintf(line, LINEBUFSIZE, format, ap);
	va_end(ap);
	if (strlen(buffer) + strlen(line) + 1 > HEADSIZE)
		return 0;
	if (prepend)
	{
		strlcat(line, buffer, HEADSIZE);
		memcpy(buffer, line, HEADSIZE);
	}
	else
		strlcat(buffer, line, HEADSIZE);
	return 1;
}

void
do_script(const char *path, const char *base, const char *file, const char *engine, int showheader)
{
	unsigned long		writetodo;
	off_t			totalwritten;
	char			errmsg[MYBUFSIZ], fullpath[XS_PATH_MAX],
				request[MYBUFSIZ], *temp,
				input[RWBUFSIZE], line[LINEBUFSIZE],
				head[HEADSIZE];
	const	char		*argv1, *header;
	int			p[2], nph, dossi, chldstat;
	ssize_t			written;
	unsigned	int	left;
#ifdef		HANDLE_SSL
	char			inbuf[RWBUFSIZE];
	int			q[2];
	int			ssl_post = 0;
	size_t		tobewritten;
#endif		/* HANDLE_SSL */
#ifdef		HAVE_SETRLIMIT
	struct	rlimit		limits;
#endif		/* HAVE_SETRLIMIT */
	struct	sigaction	action;
	struct	stat		statbuf;

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

	if (!engine && !stat(fullpath, &statbuf) && !(statbuf.st_mode & S_IXUSR))
	{
		server_error("403 File permissions deny access", "NOT_AVAILABLE");
		return;
	}

	setenv("SCRIPT_FILENAME", fullpath, 1);
	setenv("REDIRECT_STATUS", "200", 1);

	nph = (!strncmp(file, "nph-", 4) || strstr(file, "/nph-"));
	if (config.usessi)
		dossi = (!strncmp(file, "ssi-", 4) || strstr(file, "/ssi-"));
	else
		dossi = 0;
	p[0] = p[1] = -1;
	if (1 /* !nph || do_ssl */)
	{
		if (pipe(p))
		{
			snprintf(errmsg, MYBUFSIZ, "500 pipe() failed: %s", strerror(errno));
			if (showheader)
				xserror(errmsg);
			else
				secprintf("[%s]\n", errmsg);
			goto END;
		}
	}

#ifdef		HANDLE_SSL
	q[0] = q[1] = -1;
	if ((ssl_post = !strcasecmp("POST", getenv("REQUEST_METHOD"))))
	{
		char	*expect = getenv("HTTP_EXPECT");

		if (pipe(q))
		{
			snprintf(errmsg, MYBUFSIZ, "500 pipe() failed: %s",
				strerror(errno));
			if (showheader)
				xserror(errmsg);
			else
				secprintf("[%s]\n", errmsg);
			goto END;
		}
		if (expect && strcasestr(expect, "100-continue"))
			secprintf("%s 100 Continue\r\n\r\n", httpver);
	}
#endif		/* HANDLE_SSL */

	switch(child = fork())
	{
	case -1:
		snprintf(errmsg, MYBUFSIZ, "500 fork() failed: %s", strerror(errno));
		if (showheader)
			xserror(errmsg);
		else
			secprintf("[%s]\n", errmsg);
		goto END;
	case 0:
#ifdef		HAVE_SETRLIMIT
#ifdef		RLIMIT_CPU
		limits.rlim_cur = 60 * (rlim_t)config.scriptcpulimit;
		limits.rlim_max = 10 + limits.rlim_cur;
		setrlimit(RLIMIT_CPU, &limits);
#endif		/* RLIMIT_CPU */
#ifdef		RLIMIT_CORE
		limits.rlim_cur = limits.rlim_max = 0;
		setrlimit(RLIMIT_CORE, &limits);
#endif		/* RLIMIT_CORE */
#endif		/* HAVE_SETRLIMIT */

		dup2(p[1], 1);

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
			warn("setpriority");
#endif		/* HAVE_SETPRIORITY */

#ifdef		HAVE_PERL
		if (engine && !strcmp(engine, "internal:perl"))
		{
			perlargs[0] = fullpath;
			perl_call_argv("Embed::Persistent::eval_file",
				G_DISCARD | G_EVAL, perlargs);
			return;
		}
		else
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
		if (engine && !strcmp(engine, "internal:python"))
		{
			FILE	*fp = fopen(fullpath, "r");
			PyRun_SimpleFile(fp, fullpath);
			fclose(fp);
			return;
		}
		else
#endif		/* HAVE_PERL */
		if (engine)
		{
			const char	meta[] = " \t&();<>|{}$%";

			/* let shell handle engines containing metacharacters */
			if (engine[strcspn(engine, meta)])
			{
				int		len, pos;
				char	*buffer, *pengine;

				len = 2 + strlen(engine) + strlen(fullpath);
				if ((buffer = (char *)malloc(len)))
				{
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
			}
			else
				(void) execl(engine, engine, fullpath, argv1, NULL);
		}
		else
			(void) execl(fullpath, file, argv1, NULL);
		/* no need to give local path info to the visitor */
		if (nph)
		{
			snprintf(errmsg, MYBUFSIZ, "500 execl(): %s",
				/* fullpath, */ strerror(errno));
			xserror(errmsg);
		}
		else
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[execl() failed: %s]",
				strerror(errno));
			warn("[%s] execl(`%s') failed",
				currenttime, engine ? engine : fullpath);
		}
		exit(1);
	default:
		close(p[1]);
#ifdef		HANDLE_SSL
		if (ssl_post)
			close(q[0]);
#endif		/* HANDLE_SSL */
		break;
	}

#ifdef		HANDLE_SSL
	if (ssl_post)
	{
		writetodo = strtoul(getenv("CONTENT_LENGTH"), NULL, 10);
		while (writetodo > 0)
		{
			int	offset;
			int	result;

			tobewritten = writetodo > RWBUFSIZE ? RWBUFSIZE : writetodo;
			result = secread(0, inbuf, tobewritten);
			if (result < 0)
				goto END;
			tobewritten = result;
			offset = 0;
			while ((result = write(q[1], inbuf + offset, tobewritten - offset)) < (int)(tobewritten - offset))
			{
				if ((result < 0) && (errno != EINTR))
				{
					warn("[Connection closed (fd = %d, todo = %ld]",
						q[1], writetodo);
					goto END;
				}
				else if (result > 0)
					offset += result;
			}
			writetodo -= tobewritten;
		}

		close(q[1]);
	}
#endif		/* HANDLE_SSL */
	head[0] = '\0';
	initreadmode(1);
	if (!nph)
	{
		int	ctype = 0, status = 0, lastmod = 0, server = 0;
		int first = 1;

		for (;;)
		{
			if (readline(p[0], line, sizeof(line)) != ERR_NONE)
			{
				if (showheader)
					xserror("503 Script did not end header");
				else
					secprintf("[Script did not end header]\n");
				goto END;
			}
			header = skipspaces(line);
			if (!header[0])
				break;
			if (!showheader)
				/* silently discard headers */
				continue;
			if (first)
				first = 0;

			/* Look for status header */
			if (!status)
			{
				if (!strncasecmp(header, "Status:", 7))
				{
					status = 1;
					append(head, 1, "%s %s\r\n",
						httpver, skipspaces(header + 7));
					continue;
				}
				else if (!strncasecmp(header, "Location:", 9))
				{
					status = 1;
					append(head, 1, "%s 302 Moved\r\n", httpver);
				}
			}

			if (!strncasecmp(header, "Location:", 9))
			{
				char location[MYBUFSIZ];

				strlcpy(location, skipspaces(header + 9), MYBUFSIZ);
				switch(location[0])
				{
				case '/':
					if (!strcmp(cursock->port, "http"))
						append(head, 0, "Location: http://%s%s\r\n",
							current->hostname, location);
					else if (cursock->usessl && !strcmp(cursock->port, "https"))
						append(head, 0, "Location: https://%s%s\r\n",
							current->hostname, location);
					else if (cursock->usessl)
						append(head, 0, "Location: https://%s:%s%s\r\n",
							current->hostname, cursock->port, location);
					else
						append(head, 0, "Location: http://%s:%s%s\r\n",
							current->hostname, cursock->port, location);
					break;
				case 0:
					break;
				default:
					append(head, 0, "Location: %s\r\n", location);
					break;
				}
			}
			else if (!strncasecmp(header, "Content-type:", 13))
			{
				ctype = 1;
				append(head, 0, "Content-type: %s\r\n",
					skipspaces(header + 13));
			}
			else if (!strncasecmp(header, "Last-modified:", 14))
			{
				append(head, 0, "Last-modified: %s\r\n",
					skipspaces(header + 14));
				lastmod = 1;
			}
			else if (!strncasecmp(header, "Cache-control:", 14))
			{
				if (headers >= 11)
					append(head, 0, "Cache-control: %s\r\n",
						skipspaces(header + 14));
				else
					append(head, 0, "Pragma: no-cache\r\n");
			}
			else if (!strncasecmp(header, "Server:", 7))
			{
				/* Append value to SERVER_IDENT */
				if (!strncasecmp(skipspaces(header + 7),
					SERVER_IDENT, strlen(SERVER_IDENT)))
				{
					append(head, 0, "Server: %s\r\n",
						skipspaces(header + 7));
				}
				else
				{
					append(head, 0, "Server: %s %s\r\n",
						SERVER_IDENT,
						skipspaces(header + 7));
				}
				server = 1;
			}
			else if (!strncasecmp(header, "Date:", 5))
			{
				/* Thank you, I do know how to tell time */
			}
			else
				append(head, 0, "%s\r\n", header);
		}
		if (showheader)
		{
			if (!status)
				append(head, 1, "%s 200 OK\r\n", httpver);
			if (!ctype)
				append(head, 0, "Content-type: text/html\r\n");
			setcurrenttime();
			if (!lastmod)
				append(head, 0, "Last-modified: %s\r\n",
					currenttime);
			if (!server)
				append(head, 0, "Server: %s\r\n", SERVER_IDENT);
			if (headers >= 11)
				append(head, 0, "Transfer-encoding: chunked\r\n");
			append(head, 0, "Date: %s\r\n", currenttime);
			secprintf("%s\r\n", head);
			if (headers >= 11)
				chunked = 1;
		}
	}
	else /* nph */
	{
		for (;;)
		{
			if (readline(p[0], line, sizeof(line)) != ERR_NONE)
			{
				if (showheader)
					xserror("503 Script did not end header");
				else
					secprintf("[Script did not end header]\n");
				goto END;
			}
			if (showheader)
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
		for (;;)
		{
			int result = secread(p[0], input, RWBUFSIZE);

			if (result < 0)
			{
				if (errno == EAGAIN)
				{
					usleep(300);
					continue;
				}
				secprintf("[read() error from CGI: %s]", strerror(errno));
				break;
			}
			else if (!result)
				break;
			/* result > 0 */
			writetodo = result; temp = input;
			while (writetodo > 0)
			{
				written = secwrite(temp, writetodo);
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

	if (!getenv("ERROR_CODE"))
	{
		char	*qs, *pi;

		pi = getenv("PATH_INFO");
		if ((qs = getenv("QUERY_STRING")))
			snprintf(request, MYBUFSIZ, "%s%s?%s",
				path, pi ? pi : "", qs);
		else
			snprintf(request, MYBUFSIZ, "%s%s",
				path, pi ? pi : "");
		logrequest(request, totalwritten);
	}
	END:
	fflush(stdout); close(p[0]); close(p[1]);
	fflush(stderr);
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
	waitpid(child, &chldstat, 0);
}
