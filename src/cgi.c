/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: cgi.c,v 1.104 2005/09/23 16:18:08 johans Exp $ */

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
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */
#include	<ctype.h>
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */
#include	<stdarg.h>
#ifdef		HANDLE_PERL
#include	<EXTERN.h>
#include	<perl.h>
#endif		/* HANDLE_PERL */

#include	"httpd.h"
#include	"ssi.h"
#include	"ssl.h"
#include	"cgi.h"
#include	"extra.h"
#include	"setenv.h"
#include	"htconfig.h"

static	const	char	*skipspaces(const char *);
static	void		time_is_up(int);
static	int		eat_content_length(void);

#ifdef		HANDLE_PERL
const	char *	perlargs[] = { "", NULL };
extern	PerlInterpreter *my_perl;
#endif		/* HANDLE_PERL */

static pid_t			child;


static const char *
skipspaces(const char *string)
{
	while ((*string == ' ') || (*string == '\t'))
		string++;
	return(string);
}

static	int
eat_content_length(void)
{
	int		to_read, received;
	char		*colen, buf[MYBUFSIZ];

	if (!(colen = getenv("CONTENT_LENGTH")))
		return 0;

	to_read = atoi(colen);

	while (to_read > 0)
	{
		if ((received = read(1, buf, MYBUFSIZ)) < 0)
		{
			if ((errno == EINTR))
				continue;
			else
			{
				return 1;
			}
		}
		to_read -= received;
	}

	return 0;
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
}

static	int
append(char *buffer, int prepend, const char *format, ...)
{
	va_list	ap;
	char	line[HEADSIZE];

	va_start(ap, format);
	vsnprintf(line, HEADSIZE, format, ap);
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
	long			received, writetodo,
				totalwritten;
	char			errmsg[MYBUFSIZ], fullpath[XS_PATH_MAX],
				request[MYBUFSIZ],
				*temp, *nextslash,
				head[HEADSIZE];
	const	char		*argv1, *header;
	int			p[2], r[2], nph, count, dossi,
				written;
	unsigned	int	left;
#ifdef		HANDLE_SSL
	char			inbuf[MYBUFSIZ];
	int			q[2];
	int			ssl_post = 0;
	int			readerror;
	ssize_t		tobewritten;
#endif		/* HANDLE_SSL */
#ifdef		HAVE_SETRLIMIT
	struct	rlimit		limits;
#endif		/* HAVE_SETRLIMIT */
	FILE			*auth;
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

	left = alarm(60 * config.script_timeout); fflush(stdout);
	unsetenv("SCRIPT_NAME");
	unsetenv("REDIRECT_STATUS");

	/* snip++ */

	snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);

	setenv("SCRIPT_NAME", path, 1);
	setenv("SCRIPT_FILENAME", fullpath, 1);
	setenv("REDIRECT_STATUS", "200", 1);

	if (showheader)
	{
		snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);
		if ((nextslash = strrchr(fullpath, '/')))
		{
			/* TBD */
			strcpy(nextslash + 1, AUTHFILE);
			if ((auth = fopen(fullpath, "r")))
			{
				if (check_auth(auth))
				{
					(void) eat_content_length();
					goto END;
				}
			}
		}
		snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);
	}

	nph = (!strncmp(file, "nph-", 4) || strstr(file, "/nph-"));
	dossi = (!strncmp(file, "ssi-", 4) || strstr(file, "/ssi-"));
	p[0] = p[1] = r[0] = r[1] = -1;
	pipe(r);
	if (1 /* !nph || do_ssl */)
	{
		if (pipe(p))
		{
			snprintf(errmsg, MYBUFSIZ, "500 pipe() failed: %s", strerror(errno));
			if (showheader)
				error(errmsg);
			else
				secprintf("[%s]\n", errmsg);
			goto END;
		}
	}

#ifdef		HANDLE_SSL
	q[0] = q[1] = -1;
	if ((ssl_post = !strcmp("POST", getenv("REQUEST_METHOD"))))
	{
		if (pipe(q))
		{
			snprintf(errmsg, MYBUFSIZ, "500 pipe() failed: %s",
				strerror(errno));
			if (showheader)
				error(errmsg);
			else
				secprintf("[%s]\n", errmsg);
			goto END;
		}
	}
#endif		/* HANDLE_SSL */

	switch(child = fork())
	{
	case -1:
		snprintf(errmsg, MYBUFSIZ, "500 fork() failed: %s", strerror(errno));
		if (showheader)
			error(errmsg);
		else
			secprintf("[%s]\n", errmsg);
		goto END;
	case 0:
#ifdef		HAVE_SETRLIMIT
#ifdef		RLIMIT_CPU
		limits.rlim_cur = 60 * (rlim_t)config.script_cpu_limit;
		limits.rlim_max = 10 + 60 * (rlim_t)config.script_cpu_limit;
		setrlimit(RLIMIT_CPU, &limits);
#endif		/* RLIMIT_CPU */
#ifdef		RLIMIT_CORE
		limits.rlim_cur = limits.rlim_max = 0;
		setrlimit(RLIMIT_CORE, &limits);
#endif		/* RLIMIT_CORE */
#ifdef		RLIMIT_MEMLOCK
		limits.rlim_cur = limits.rlim_max = 1;
		setrlimit(RLIMIT_MEMLOCK, &limits);
#endif		/* RLIMIT_MEMLOCK */
#endif		/* HAVE_SETRLIMIT */

		dup2(p[1], 1);
		dup2(r[1], 2);
#ifdef		HANDLE_SSL
		/* Posting via SSL takes a lot of extra work */
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

		for (count = 3; count < 64; count++)
			close(count);

		if (!origeuid)
		{
			/* Set uid first, euid later! */
			uid_t uid = geteuid();
			gid_t gid = getegid();
			if (current != config.users)
			{
				uid = current->userid;
				gid = current->groupid;
			}

			/* mind you, we need to do this as root */
			seteuid(origeuid);
			setegid(origegid);
			setgid(gid);
			setegid(gid);
			setuid(uid);
			seteuid(uid);
			if (uid != geteuid() || gid != getegid())
			{
				secprintf("Content-type: text/plain\r\n\r\n");
				secprintf("[Invalid UID setting]\n");
				secprintf("UID = %ld, EUID = %ld\n",
					(long)getuid(), (long)geteuid());
				secprintf("GID = %ld, EGID = %ld\n",
					(long)getgid(), (long)getegid());
				exit(1);
			}
		}
		setenv("PATH", SCRIPT_PATH, 1);
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

#ifdef		HANDLE_PERL
		if (engine && !strcmp(engine, "internal:perl"))
		{
			perlargs[0] = fullpath;
			perl_call_argv("Embed::Persistent::eval_file",
				G_DISCARD | G_EVAL, perlargs);
			return;
		}
		else
#endif		/* HANDLE_PERL */
		if (engine)
			(void) execl(engine, engine, fullpath, argv1, NULL);
		else
			(void) execl(fullpath, file, argv1, NULL);
		/* no need to give local path info to the visitor */
		if (nph)
		{
			snprintf(errmsg, MYBUFSIZ, "500 execl(): %s",
				/* fullpath, */ strerror(errno));
			error(errmsg);
		} else
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[execl() failed: %s]",
				strerror(errno));
			fprintf(stderr, "[%s] execl(`%s') failed: %s\n",
				currenttime, engine ? engine : fullpath, strerror(errno));
		}
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
	if (ssl_post)
	{
		writetodo = atoi(getenv("CONTENT_LENGTH"));
		while (writetodo > 0)
		{
			int	offset;

			tobewritten = writetodo > MYBUFSIZ ? MYBUFSIZ : writetodo;
			while (!(tobewritten = secread(0, inbuf, tobewritten)))
				mysleep(1);
			if ((tobewritten < 0) && ((readerror = ERR_get_error()))) {
				fprintf(stderr, "SSL Error: %s\n",
					ERR_reason_error_string(readerror));
				goto END;
			}
			offset = 0;
			while ((written = write(q[1], inbuf + offset, tobewritten - offset)) < tobewritten - offset) {
				if ((written < 0) && (errno != EINTR))
				{
					fprintf(stderr, "[Connection closed: %s (fd = %d, todo = %ld]\n",
						strerror(errno), q[1], writetodo);
					goto END;
				} else if (written < 0)
					offset += written;
			}
			writetodo -= tobewritten;
		}

		close(q[1]);
		close(0);
	}
#endif		/* HANDLE_SSL */
	setreadmode(READCHAR, 1);
	head[0] = '\0';
	if (!nph)
	{
		int	ctype = 0, status = 0, lastmod = 0, server = 0;

		while (1)
		{
			if (readline(p[0], errmsg) != ERR_NONE)
			{
				if (showheader)
					error("503 Script did not end header");
				else
					secprintf("[Script did not end header]\n");
				goto END;
			}
			received = strlen(errmsg);
			while ((received > 0) && (errmsg[received - 1] < 32))
				errmsg[--received] = 0;
			header = skipspaces(errmsg);
			if (!header[0])
				break;
			if (!showheader)
				continue;

			/* Look for status header */
			if (!status)
			{
				if (!strncasecmp(header, "Status:", 7))
				{
					status = 1;
					append(head, 1, "%s %s\r\n",
						version, skipspaces(header + 7));
					continue;
				}
				else if (!strncasecmp(header, "Location:", 9))
				{
					status = 1;
					append(head, 1, "%s 302 Moved\r\n", version, head);
				}
			}

			if (!strncasecmp(header, "Location:", 9))
			{
				char location[MYBUFSIZ];

				strlcpy(location, skipspaces(header + 9), MYBUFSIZ);
				switch(location[0])
				{
				case '/':
					if (!strcmp(config.port, "http"))
						append(head, 0, "Location: http://%s%s\r\n",
							current->hostname, location);
					else if (config.usessl && !strcmp(config.port, "https"))
						append(head, 0, "Location: https://%s%s\r\n",
							current->hostname, location);
					else if (config.usessl)
						append(head, 0, "Location: https://%s:%s%s\r\n",
							current->hostname, config.port, location);
					else
						append(head, 0, "Location: http://%s:%s%s\r\n",
							current->hostname, config.port, location);
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
				if (showheader >= 11)
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
				append(head, 1, "%s 200 OK\r\n", version);
			if (!ctype)
				append(head, 0, "Content-type: text/html\r\n");
			setcurrenttime();
			if (!lastmod)
				append(head, 0, "Last-modified: %s\r\n",
					currenttime);
			if (!server)
				append(head, 0, "Server: %s\r\n", SERVER_IDENT);
			append(head, 0, "Date: %s\r\n", currenttime);
			secprintf("%s\r\n", head);
		}
	} else
	{
		while (1)
		{
			if (readline(p[0], errmsg) != ERR_NONE)
			{
				if (showheader)
					error("503 Script did not end header");
				else
					secprintf("[Script did not end header]\n");
				goto END;
			}
			received = strlen(errmsg);
			if (showheader)
				secprintf("%s", errmsg);
			while ((received > 0) && (errmsg[received - 1] < 32))
				errmsg[--received] = 0;
			if (!errmsg[0])
				break;
		}
	}
	fflush(stdout);

	setreadmode(READBLOCK, 0);
	totalwritten = 0;
#ifdef		WANT_SSI
	if (dossi)
	{
		size_t ttw = 0;
		/* Parse the output of CGI script for SSI directives */
		sendwithdirectives(p[0], &ttw);
		totalwritten = ttw;
	}
	else
#endif		/* WANT_SSI */
	for (;;)
	{
		received = read(p[0], errmsg, MYBUFSIZ);
		if (received < 0)
		{
			if (errno == EINTR || errno == EWOULDBLOCK)
			{
				usleep(300);
				continue;
			}
			secprintf("[read() error from CGI: %s]", strerror(errno));
			break;
		} else if (received == 0)
			break;
		writetodo = received; temp = errmsg;
		while (writetodo > 0)
		{
			written = secwrite(fileno(stdout), temp, writetodo);
			if (written < 0)
			{
				if ((errno == EINTR) || (errno == EWOULDBLOCK))
				{
					usleep(300);
					continue;
				}
				secprintf("[Connection closed: %s (fd = %d, temp = %p, todo = %ld]\n",
					strerror(errno), fileno(stdout), temp,
					writetodo);
				goto END;
			} else if (!written)
			{
				secprintf("[Connection closed: couldn't write]\n");
				goto END;
			} else
			{
				writetodo -= written;
				temp += written;
			}
		}
		totalwritten += received;
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
	close(p[0]); close(p[1]); fflush(stdout);
	close(r[0]); close(r[1]); fflush(stdout);
#ifdef		HANDLE_SSL
	if (ssl_post)
	{
		close(q[0]); close(q[1]);
		close(0); close(1);
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
}
