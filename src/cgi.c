/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: cgi.c,v 1.58 2002/05/09 09:16:42 johans Exp $ */

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
#ifndef		NONEWSTYLE
#include	<stdarg.h>
#else		/* NONEWSTYLE */
#include	<optarg.h>
#endif		/* NONEWSTYLE */
#ifdef		HANDLE_PERL
#include	<EXTERN.h>
#include	<perl.h>
#endif		/* HANDLE_PERL */

#include	"httpd.h"
#include	"local.h"
#include	"procname.h"
#include	"ssi.h"
#include	"cgi.h"
#include	"extra.h"
#include	"path.h"
#include	"convert.h"
#include	"setenv.h"
#include	"htconfig.h"

#ifndef		NOFORWARDS
static	const	char	*skipspaces	PROTO((const char *));
static	VOID	time_is_up		PROTO((int));
#endif		/* NOFORWARDS */
#ifdef		HANDLE_PERL
static	char *	perlargs[] = { "", NULL };
#endif		/* HANDLE_PERL */

pid_t			child;


static	const	char	*
skipspaces DECL1C(char *, string)
{
	while ((*string == ' ') || (*string == '\t'))
		string++;
	return(string);
}

static	int
eat_content_length DECL0
{
	int		to_read, received;
	char		buf[MYBUFSIZ];

	to_read = atoi(getenv("CONTENT_LENGTH"));

	while (to_read > 0)
	{
		if ((received = read(1, buf, MYBUFSIZ)) == -1)
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

static	VOID
time_is_up DECL1(int, sig)
{
	if (child != (pid_t)-1)
	{
		killpg(child, SIGTERM);
		mysleep(1);
		killpg(child, SIGKILL);
	}
	alarm_handler(sig);
}

#ifndef		NONEWSTYLE
static	int
append(char *buffer, int prepend, const char *format, ...)
#else		/* NONEWSTYLE */
static	int
append(buffer, prepend, format, va_list)
char	*buffer;
int		prepend;
const	char	*format;
va_decl
#endif		/* NONEWSTYLE */
{
	va_list	ap;
	size_t	len;
	char	line[HEADSIZE];

	va_start(ap, format);
	vsnprintf(line, HEADSIZE, format, ap);
	va_end(ap);
	line[HEADSIZE - 1] = '\0';
	if (strlen(buffer) + strlen(line) + 1 > HEADSIZE)
		return 0;
	if (prepend)
	{
		len = HEADSIZE - strlen(line) - 1;
		strncat(line, buffer, len);
		memcpy(buffer, line, HEADSIZE);
	}
	else
	{
		len = HEADSIZE - strlen(buffer);
		strncat(buffer, line, len);
	}
	return 1;
}

extern	VOID
do_script DECL3CC_(char *, path, char *, engine, int, showheader)
{
	struct	stat		statbuf;
	uid_t			savedeuid, currentuid;
	gid_t			savedegid, currentgid;
	long			size, received, writetodo,
				totalwritten;
	char			errmsg[MYBUFSIZ], fullpath[XS_PATH_MAX],
				base[XS_PATH_MAX], *temp, *nextslash,
				tempbuf[XS_PATH_MAX + 32], head[HEADSIZE];
	const	char		*file, *argv1, *header;
	int			p[2], nph, count, nouid, dossi, was_slash,
				written;
	unsigned	int	left;
#ifdef		HANDLE_SSL
	char			inbuf[MYBUFSIZ];
	int			q[2];
	int			ssl_post = 0;
	int			readerror;
	long		tobewritten;
#endif		/* HANDLE_SSL */
#ifdef		USE_SETRLIMIT
	struct	rlimit		limits;
#endif		/* USE_SETRLIMIT */
	const	struct	passwd	*userinfo;
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

	left = alarm(360); fflush(stdout);
	unsetenv("PATH_INFO"); unsetenv("PATH_TRANSLATED");
	unsetenv("QUERY_STRING"); unsetenv("SCRIPT_NAME");
	unsetenv("REDIRECT_STATUS");
	savedeuid = savedegid = -1;
	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); setegid(origegid);
	}

	userinfo = NULL; was_slash = 0;
	if ((path[0] == '/') && ((path[1] == '?') || !path[1]))
		was_slash = 1;

	if (path[0] != '/')
	{
		if (showheader)
			error("403 Invalid pathname");
		else
			secprintf("[Invalid pathname]\n");
		goto END;
	}
	currentgid = -1;
	if (path[1] == '~')
	{
		strncpy(name, path + 2, 16);
		name[15] = 0;
		if ((temp = strchr(name, '/')))
			*temp = 0;
		if (!(userinfo = getpwnam(name)))
		{
			if (showheader)
				error("404 User is unknown");
			else
				secprintf("[User `%s' is unknown]\n", name);
			goto END;
		}
		if (transform_user_dir(base, userinfo, showheader))
		{
			if (!showheader)
				secprintf("[User directory error]\n");
			goto END;
		}
		size = strlen(base);
#ifdef		HANDLE_SCRIPT
		if (!engine)
#endif		/* HANDLE_SCRIPT */
		{
			strncpy(base + size, config.system->execdir, XS_PATH_MAX-size-1);
			base[XS_PATH_MAX-2] = '\0';
			strcat(base + size, "/");
		}
		if (!origeuid)
		{
			setegid(currentgid = userinfo->pw_gid);
			setgroups(1, (const gid_t *)&userinfo->pw_gid);
			seteuid(userinfo->pw_uid);
		}
		if (!(currentuid = geteuid()))
		{
			if (showheader)
				error("500 Effective UID is not valid");
			else
				secprintf("[UID error]\n");
			goto END;
		}
		file = path + strlen(name) + 3;
	} else
	{
#ifdef		SIMPLE_VIRTUAL_HOSTING
		if (getenv("HTTP_HOST"))
		{
			strncpy(base, calcpath(getenv("HTTP_HOST")), XS_PATH_MAX-1);
			base[XS_PATH_MAX-2] = '\0';
			if (stat(base, &statbuf) || !S_ISDIR(statbuf.st_mode))
				strncpy(base, calcpath(engine
					? config.system->htmldir : rootdir), XS_PATH_MAX-1);
#ifdef		VIRTUAL_UID
			else
			{
				/* We got a virtual host, now set euid */
				if (!origeuid)
				{
					setegid(currentgid = statbuf.st_gid);
					setgroups(1, (const gid_t *)&statbuf.st_gid);
					seteuid(statbuf.st_uid);
				}
				if (!(currentuid = geteuid()))
				{
					if (showheader)
						error("500 Effective UID is not valid");
					else
						secprintf("[UID error]\n");
					goto END;
				}
			}
#endif		/* VIRTUAL_UID */
		}
		else
#endif		/* SIMPLE_VIRTUAL_HOSTING */
			strncpy(base, calcpath(engine ? config.system->htmldir : rootdir),
				XS_PATH_MAX-1);
		strcat(base, "/");
		base[XS_PATH_MAX-2] = '\0';
		if (engine)
		{
			file = path + 1;
		}
		else if (!was_slash)
		{
			file = path + 1;
			strncat(base, config.system->phexecdir, XS_PATH_MAX-strlen(base)-1);
			base[XS_PATH_MAX-2] = '\0';
			strcat(base, "/");
		} else
		{
			snprintf(tempbuf, sizeof(tempbuf), "cgi/nph-slash%s", path + 1);
			tempbuf[sizeof(tempbuf)-1] = '\0';
			file = tempbuf;
			strncat(base, config.system->phexecdir, XS_PATH_MAX-strlen(base)-1);
			base[XS_PATH_MAX-2] = '\0';
			strcat(base, "/");
		}

		if (!origeuid)
		{
			setegid(currentgid = config.groupid);
			setgroups(1, &config.groupid);
			seteuid(config.userid);
		}
		if (!(currentuid = geteuid()))
		{
			if (showheader)
				error("500 Effective UID is not valid");
			else
				secprintf("[UID error]\n");
			goto END;
		}
	}

	size = strlen(config.system->execdir);
#ifdef		HANDLE_SCRIPT
	if (engine)
		size = -1;
	else
#endif		/* HANDLE_SCRIPT */
	if (strncmp(file, config.system->execdir, size) || (file[size] != '/'))
	{
		if (showheader)
			error("403 Not a CGI path");
		else
			secprintf("[Not a CGI path]\n");
		goto END;
	}

	strncpy(name, file + size + 1, XS_PATH_MAX - 64);
	name[XS_PATH_MAX - 64] = '\0';
	argv1 = NULL;
	if ((temp = strchr(name, '?')))
	{
		*(temp++) = 0;
		setenv("QUERY_STRING", temp, 1);
		if (!strchr(temp, '='))
			argv1 = temp;
	}

	nextslash = name;
	for (;;)
	{
		if (!(nextslash = strchr(nextslash, '/')))
			break;
		*nextslash = 0;
		snprintf(fullpath, XS_PATH_MAX, "%s%s", base, name);
		fullpath[XS_PATH_MAX-1] = '\0';
		if (stat(fullpath, &statbuf))
		{
			if (showheader)
				error("403 Nonexistent CGI binary");
			else
				secprintf("[Nonexistent CGI binary]\n");
			goto END;
		}
		if ((statbuf.st_mode & S_IFMT) == S_IFREG)
			break;
		*(nextslash++) = '/';
	}
	if (nextslash)
	{
		*nextslash = '/';
		setenv("PATH_INFO", nextslash, 1);
		setenv("PATH_TRANSLATED", convertpath(nextslash), 1);
		*nextslash = 0;
	}

	if (strstr(name, "..") || strstr(name, "/.x"))
	{
		if (showheader)
			error("400 Invalid URI");
		else
			secprintf("[Invalid URI]\n");
		goto END;
	}
#ifdef		HANDLE_SCRIPT
	if (engine)
	{
		if (userinfo)
			snprintf(fullpath, XS_PATH_MAX, "/~%s/%s", userinfo->pw_name, name);
		else
			snprintf(fullpath, XS_PATH_MAX, "/%s", name);
	}
	else
#endif		/* HANDLE_SCRIPT */
	if (userinfo)
		snprintf(fullpath, XS_PATH_MAX, "/~%s/%s/%s", userinfo->pw_name,
			config.system->execdir, name);
	else
		snprintf(fullpath, XS_PATH_MAX, "/%s/%s", config.system->execdir, name);
	fullpath[XS_PATH_MAX-1] = '\0';
	if (was_slash)
		setenv("SCRIPT_NAME", "/", 1);
	else
		setenv("SCRIPT_NAME", fullpath, 1);
	setenv("REDIRECT_STATUS", "200", 1);

	if (showheader)
	{
		snprintf(fullpath, XS_PATH_MAX, "%s%s", base, name);
		fullpath[XS_PATH_MAX-1] = '\0';
		if ((nextslash = strrchr(fullpath, '/')))
		{
			/* TBD */
			strcpy(nextslash + 1, AUTHFILE);
			if ((auth = fopen(fullpath, "r")))
			{
				if (check_auth(auth))
				{
					eat_content_length();
					goto END;
				}
			}
		}
	}

	snprintf(fullpath, XS_PATH_MAX, "%s%s", base, name);
	fullpath[XS_PATH_MAX-1] = '\0';
	if (stat(fullpath, &statbuf))
	{
		snprintf(base, XS_PATH_MAX-1, "%s/%s",
			calcpath(HTTPD_ROOT), config.system->execdir);
		snprintf(fullpath, XS_PATH_MAX-1, "%s/%s/%s",
			calcpath(HTTPD_ROOT), config.system->execdir, name);
		if (stat(fullpath, &statbuf))
		{
			if (showheader)
				error("403 Nonexistent CGI binary");
			else
				secprintf("[Nonexistent CGI binary]\n");
			goto END;
		}
	}
	if (statbuf.st_mode & (S_IWGRP | S_IWOTH))
	{
		if (showheader)
			error("403 CGI binary is writable");
		else
			secprintf("[CGI binary is writable]\n");
		goto END;
	}
	if (userinfo && (statbuf.st_uid != currentuid))
	{
		if (showheader)
			error("403 Invalid owner for CGI binary");
		else
			secprintf("[Invalid owner for CGI binary]");
		goto END;
	}
	nph = (!strncmp(name, "nph-", 4) || strstr(name, "/nph-"));
	dossi = (!strncmp(name, "ssi-", 4) || strstr(name, "/ssi-"));
	nouid = (strstr(name, "/nph-nid-") || strstr(name, "/nid-") ||
		!strncmp(name, "nph-nid-", 8) || !strncmp(name, "nid-", 4));
	p[0] = -1; p[1] = -1;
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
	if (config.usessl && (ssl_post = !strcmp("POST", getenv("REQUEST_METHOD"))))
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
#ifdef		USE_SETRLIMIT
#ifdef		RLIMIT_CPU
		limits.rlim_cur = 120; limits.rlim_max = 128;
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
#endif		/* USE_SETRLIMIT */
		if (1 /* !nph || do_ssl */)
			dup2(p[1], 1);
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
			seteuid(origeuid);
			if (nouid)
			{
				currentuid = config.userid;
				currentgid = config.groupid;
			}
			setgid(currentgid); setuid(currentuid);
			if (!getuid() || !geteuid() ||
				(getuid() != currentuid) ||
				(getgid() != currentgid))
			{
				secprintf("Content-type: text/plain\r\n\r\n");
				secprintf("[Invalid UID setting]\n");
				secprintf("UID = %ld, EUID = %ld\n",
					(long)getuid(), (long)geteuid());
				exit(1);
			}
		}
		setenv("PATH", SCRIPT_PATH, 1);
		snprintf(tempbuf, 1+strrchr(fullpath, '/') - fullpath, "%s", fullpath);
		if (chdir(tempbuf))
		{
			secprintf("Content-type: text/plain\r\n\r\n");
			secprintf("[Cannot change directory]\n");
			exit(1);
		}
#ifdef		HANDLE_SCRIPT
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
		{
			unsetenv("PATH_INFO");
			setenv("PATH_TRANSLATED", fullpath, 1);
			execl(engine, engine, fullpath, argv1, NULL);
		}
		else
#endif		/* HANDLE_SCRIPT */
			execl(fullpath, name, argv1, NULL);
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
			tobewritten = secread(0, inbuf, tobewritten);
			if ((tobewritten == -1) && ((readerror = ERR_get_error()))) {
				fprintf(stderr, "SSL Error: %s\n",
					ERR_reason_error_string(readerror));
				goto END;
			}
			offset = 0;
			while ((written = write(q[1], inbuf + offset, tobewritten - offset)) < tobewritten - offset) {
				if ((written == -1) && (errno != EINTR))
				{
					fprintf(stderr, "[Connection closed: %s (fd = %d, temp = %p, todo = %ld]\n",
						strerror(errno), q[1], temp, writetodo);
					goto END;
				} else if (written != -1)
					offset += written;
			}
			writetodo -= tobewritten;
		}

		close(q[1]);
	}
#endif		/* HANDLE_SSL */
	netbufind = netbufsiz = 0; readlinemode = READCHAR;
	head[0] = '\0';
	if (!nph)
	{
		int ctype = 0, status = 0;
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
				
				strncpy(location, skipspaces(header + 9), MYBUFSIZ);
				switch(location[0])
				{
				case '/':
					if (!strcmp(config.port, "http"))
						append(head, 0, "Location: http://%s%s\r\n",
							config.system->hostname, location);
					else if (config.usessl && !strcmp(config.port, "https"))
						append(head, 0, "Location: https://%s%s\r\n",
							config.system->hostname, location);
					else if (config.usessl)
						append(head, 0, "Location: https://%s:%s%s\r\n",
							config.system->hostname, config.port, location);
					else
						append(head, 0, "Location: http://%s:%s%s\r\n",
							config.system->hostname, config.port, location);
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
			else if (!strncasecmp(header, "Cache-control:", 14))
			{
				if (showheader >= 11)
					append(head, 0, "Cache-control: %s\r\n",
						skipspaces(header + 14));
				else
					append(head, 0, "Pragma: no-cache\r\n");
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
			append(head, 0, "Date: %s\r\nLast-modified: %s\r\nServer: %s\r\n",
				currenttime, currenttime, SERVER_IDENT);
			head[HEADSIZE-1] = '\0';
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

	readlinemode = READBLOCK;
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
		if (received == -1)
		{
			if (errno == EINTR)
				continue;
			secprintf("[read() error from CGI: %s]", strerror(errno));
			break;
		} else if (received == 0)
			break;
		writetodo = received; temp = errmsg;
		while (writetodo > 0)
		{
			written = secwrite(fileno(stdout), temp, writetodo);
			if (written == -1)
			{
				if ((errno == EINTR) || (errno == EWOULDBLOCK))
					continue;
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

	logrequest(path, totalwritten);
	END:
	close(p[0]); close(p[1]); fflush(stdout);
#ifdef		HANDLE_SSL
	if (ssl_post)
	{
		close(q[0]); close(q[1]);
	}
#endif		/* HANDLE_SSL */
	if (!origeuid)
	{
		seteuid(origeuid); setegid(savedegid); seteuid(savedeuid);
	}
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
