/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */
#ifdef		HAVE_SYS_RESOURCE_H
#include	<sys/resource.h>
#endif		/* HAVE_SYS_RESOURCE_H */
#ifdef		HAVE_SYS_MMAN_H
#include	<sys/mman.h>
#endif		/* HAVE_SYS_MMAN_H */
#include	<sys/socket.h>
#ifdef		HAVE_SYS_WAIT_H
#include	<sys/wait.h>
#endif		/* HAVE_SYS_WAIT_H */
#include	<sys/signal.h>
#include	<sys/stat.h>
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

#include	<arpa/inet.h>

#include	<fcntl.h>
#include	<stdio.h>
#include	<errno.h>
#include	<netdb.h>
#ifdef		HAVE_TIME_H
#ifdef		TIME_WITH_SYS_TIME
#include	<time.h>
#endif		/* TIME_WITH_SYS_TIME */
#endif		/* HAVE_TIME_H */
#include	<stdlib.h>
#ifndef		NONEWSTYLE
#include	<stdarg.h>
#else		/* Not not NONEWSTYLE */
#include	<varargs.h>
#endif		/* NONEWSTYLE */
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
#ifdef		HAVE_ALLOCA_H
#include	<alloca.h>
#endif		/* HAVE_ALLOCA_H */
#ifdef		HAVE_VFORK_H
#include	<vfork.h>
#endif		/* HAVE_VFORK_H */
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */
#ifdef		HANDLE_SSL
#include	<openssl/ssl.h>
#endif		/* HANDLE_SSL */
#ifdef		HANDLE_PERL
#include	<EXTERN.h>
#include	<perl.h>
#endif		/* HANDLE_PERL */

#include	"httpd.h"
#include	"methods.h"
#include	"local.h"
#include	"procname.h"
#include	"ssi.h"
#include	"extra.h"
#include	"cgi.h"
#include	"xscrypt.h"
#include	"path.h"
#include	"convert.h"
#include	"setenv.h"
#include	"mygetopt.h"
#include	"mystring.h"
#include	"htconfig.h"

#ifdef		__linux__
extern	char	*tempnam(const char *, const char *);
#endif		/* __linux__ */

#ifdef		HANDLE_COMPRESSED
#define		WANT_CTYPES	1
#endif		/* HANDLE_COMPRESSED */
#ifdef		HANDLE_SCRIPT
#define		WANT_CTYPES	1
#endif		/* HANDLE_SCRIPT */

/* Global structures */

typedef	struct	ftypes
{
	struct	ftypes	*next;
	char		name[32], ext[16];
} ftypes;

#ifdef		WANT_CTYPES
typedef	struct	ctypes
{
	struct	ctypes	*next;
	char		prog[XS_PATH_MAX], ext[16], name[16];
} ctypes;
#endif		/* WANT_CTYPES */

static	ftypes	*ftype = NULL;
#ifdef		HANDLE_COMPRESSED
static	ctypes	*ctype = NULL;
#endif		/* HANDLE_COMPRESSED */
#ifdef		HANDLE_SCRIPT
static	ctypes	*itype = NULL;
#endif		/* HANDLE_SCRIPT */
#ifdef		HANDLE_CHARSET
static	char	charset[XS_PATH_MAX];
#endif		/* HANDLE_CHARSET */
#ifdef		HANDLE_PERL
static	PerlInterpreter *	perl = NULL;
#endif		/* HANDLE_PERL */

extern	VOID
senduncompressed DECL1(int, fd)
{
#ifdef		WANT_SSI
	int		errval, html;
#endif		/* WANT_SSI */
#ifndef		HAVE_MMAP
	size_t		secreadtotal, writetotal;
#endif		/* HAVE_MMAP */
	int			size, written;
	char		modified[32];
	struct tm	reqtime;

	alarm(180);
	if ((size = lseek(fd, 0, SEEK_END)) == -1)
	{
		error("500 Cannot lseek() to end of file");
		return;
	}
	if (lseek(fd, 0, SEEK_SET))
	{
		error("500 Cannot lseek() to beginning of file");
		return;
	}
	if (headers)
	{
		char *env;
		int	dynamic = 0;

#ifdef		WANT_SSI
		/* This is extra overhead, overhead, overhead! */
		if (getfiletype(0))
		{
			char input[MYBUFSIZ];

			/* fgets is better: read() may split HTML tags! */
			while (read(fd, input, MYBUFSIZ))
				if (strstr(input, "<!--#"))
				{
					dynamic = 1;
					break;
				}
			lseek(fd, 0, SEEK_SET);
		}
#endif		/* WANT_SSI */
		if ((env = getenv("IF_MODIFIED_SINCE")))
		{
			strptime(env, "%a, %d %b %Y %T", &reqtime);
			if (!dynamic && (mktime(&reqtime) > modtime))
			{
				headonly = 1;
				secprintf("%s 304 Not modified\r\n", version);
			}
			else
				secprintf("%s 200 OK\r\n", version);
		}
		else if ((env = getenv("IF_UNMODIFIED_SINCE")))
		{
			strptime(env, "%a, %d %b %Y %T", &reqtime);
			if (dynamic || (mktime(&reqtime) > modtime))
			{
				server_error("412 Precondition failed", "PRECONDITION_FAILED");
				close(fd);
				return;
			}
			else
				secprintf("%s 200 OK\r\n", version);
		}
		else
			secprintf("%s 200 OK\r\n", version);
		stdheaders(0, 0, 0);
		if (dynamic)
		{
			if (headers >= 11)
				secprintf("Cache-control: no-cache\r\n");
			else
				secprintf("Pragma: no-cache\r\n");
		}

#ifndef		WANT_SSI
		getfiletype(1);
		secprintf("Content-length: %ld\r\n", (long)size);
#else		/* Not WANT_SSI */
		html = getfiletype(1);
		if (!html)
			secprintf("Content-length: %ld\r\n", (long)size);
#endif		/* WANT_SSI */
		if (getenv("CONTENT_ENCODING"))
		{
#ifdef		WANT_SSI
			html = 0;
#endif		/* WANT_SSI */
			secprintf("Content-encoding: %s\r\n", getenv("CONTENT_ENCODING"));
			unsetenv("CONTENT_ENCODING");
		}
		strftime(modified, sizeof(modified),
			"%a, %d %b %Y %T GMT", gmtime(&modtime));
		secprintf("Last-modified: %s\r\n\r\n", modified);
	}
#ifdef		WANT_SSI
	else
	{
		html = getfiletype(0);
		if (html)
			secprintf("\r\n");
	}
#endif		/* WANT_SSI */

	if (headonly)
		goto DONE;

	UNPARSED:
#ifdef		WANT_SSI
	if (!html)
#endif		/* WANT_SSI */
#ifdef		HAVE_MMAP
	{
		char		*buffer;

		if ((buffer = (char *)mmap((caddr_t)0, size, PROT_READ,
			MAP_SHARED, fd, 0)) == (char *)-1)
		{
			fprintf(stderr, "[%s] httpd: mmap() failed: %s\n",
				currenttime, strerror(errno));
			exit(1);
		}
		alarm((size / MINBYTESPERSEC) + 20);
		fflush(stdout);
		if ((written = secwrite(fileno(stdout), buffer, size)) != size)
		{
			if (written != -1)
				fprintf(stderr, "[%s] httpd: Aborted for `%s' (%ld of %ld bytes sent)\n",
					currenttime,
					remotehost[0] ? remotehost : "(none)",
					(long)written, (long)size);
			else
				fprintf(stderr, "[%s] httpd: Aborted for `%s'\n",
					currenttime,
					remotehost[0] ? remotehost : "(none)");
		}
		munmap(buffer, size); size = written;
		alarm(0);
	}
#else		/* Not HAVE_MMAP */
	{
		char		buffer[SENDBUFSIZE];

		writetotal = 0;
		alarm((size / MINBYTESPERSEC) + 20);
		fflush(stdout);
		while ((secreadtotal = secread(fd, buffer, SENDBUFSIZE)) > 0)
		{
			if ((written = secwrite(fileno(stdout), buffer,
				secreadtotal)) != secreadtotal)
			{
				fprintf(stderr,
					"[%s] httpd: Aborted for `%s' (No mmap) (%ld of %ld bytes sent)\n",
					currenttime,
					remotehost[0] ? remotehost : "(none)",
					writetotal + written, size);
				size = writetotal;
				alarm(0); goto DONE;
			}
			writetotal += written;
		}
		size = writetotal;
		alarm(0);
	}
#endif		/* HAVE_MMAP */
#ifdef		WANT_SSI
	else
	{
		size = 0;
		alarm((size / MINBYTESPERSEC) + 60);
		errval = sendwithdirectives(fd, (size_t *)&size);
		close(fd);
		switch(errval)
		{
		case ERR_QUIT:
			fprintf(stderr, "[%s] httpd: Aborted for `%s' (ERR_QUIT)\n",
				currenttime,
				remotehost[0] ? remotehost : "(none)");
			break;
		case ERR_CONT:
			html = 0; goto UNPARSED;
		default:
			break;
		}
	}
#endif		/* WANT_SSI */

	DONE:
	logrequest(real_path, size);
	close(fd);
}

#ifdef HANDLE_COMPRESSED
extern	VOID
sendcompressed DECL2_C(int, fd, char *, method)
{
	pid_t		pid;
	int		count, processed;
	char	prefix[] = TEMPORARYPREFIX;

#ifdef		HAVE_MKSTEMP
	if (!(processed = mkstemp(prefix)))
	{
		fprintf(stderr, "[%s] httpd: Cannot create temporary file: %s\n",
			currenttime, strerror(errno));
		error("500 Unable to open temporary file");
		exit(1);
	}
#else		/* HAVE_MKSTEMP */
	char		*tmp;

	/* Removed obsolete tempnam() call
	 * if (!(tmp = tempnam(TEMPORARYPATH, "xs-www")))
	 */
	{
		if (!(tmp = (char *)malloc(32 + strlen(TEMPORARYPREFIX))))
		{
			error("500 Out of memory in sendcompressed()");
			close(fd); return;
		}
		sprintf(tmp, "%s.%016ld", TEMPORARYPREFIX, (long)getpid());
	}
	remove(tmp);
	if ((processed = open(tmp, O_CREAT | O_TRUNC | O_RDWR | O_EXCL,
		S_IWUSR | S_IRUSR )) < 0)
	{
		fprintf(stderr, "[%s] httpd: Cannot open(`%s'): %s\n",
			currenttime, tmp, strerror(errno));
		error("500 Unable to open temporary file");
		exit(1);
	}
	remove(tmp); free(tmp); fflush(stdout);
#endif		/* HAVE_MKSTEMP */
	switch(pid = fork())
	{
	case -1:
		fprintf(stderr, "[%s] httpd: Cannot fork(): %s\n",
			currenttime, strerror(errno));
		error("500 Cannot fork() in sendcompressed()");
		close(fd); close(processed); return;
	case 0:
#ifdef		HAVE_SETSID
		if (setsid() == -1)
		{
			error("500 setsid() failed");
			exit(1);
		}
#else		/* Not HAVE_SETSID */
		if (setpgrp(getpid(), 0) == -1)
		{
			error("500 setpgrp() failed");
			exit(1);
		}
#endif		/* HAVE_SETSID */
		dup2(fd, 0); dup2(processed, 1);
		for (count = 3; count < 64; count++)
			close(count);
		execl(method, method, NULL);
		fprintf(stderr, "[%s] httpd: Cannot execl(`%s'): %s\n",
			currenttime, method, strerror(errno));
		error("500 Cannot start conversion program");
		exit(1);
	default:
		close(fd);
		if (!kill(pid, 0) && mysleep(180))
		{
			close(processed);
			killpg(pid, SIGTERM);
			mysleep(3);
			killpg(pid, SIGKILL);
			error("500 Conversion program timed out");
			return;
		}
		if (!kill(pid, 0))
		{
			close(processed);
			killpg(pid, SIGKILL);
			error("500 Interrupted during conversion");
			return;
		}
	}
	senduncompressed(processed);
}
#endif		/* HANDLE_COMPRESSED */

#ifdef		RESTRICTXS
extern	int
allowxs DECL1(char *, file)
{
	char	*remoteaddr;
	char	allowhost[256];
	FILE	*rfile;

	if (!(remoteaddr = getenv("REMOTE_ADDR")))
		return 0; /* access denied */
	if (!(rfile = fopen(file, "r")))
		return 0; /* access denied */

	while (fgets(allowhost, 256, rfile))
	{
		allowhost[255] = '\0';
		if (strlen(allowhost) &&
			allowhost[strlen(allowhost) - 1] == '\n')
		    allowhost[strlen(allowhost) - 1] = '\0';

		if (strlen(allowhost) &&
			!strncmp(remoteaddr, allowhost, strlen(allowhost)))
		{
			fclose(rfile);
			return 1; /* access granted */
		}
	}

	fclose(rfile);
	return 0;
}
#endif		/* RESTRICTXS */

extern	VOID
do_get DECL1(char *, params)
{
	char			*temp, *file, auth[XS_PATH_MAX], base[XS_PATH_MAX],
			total[XS_PATH_MAX];
	const	char		*filename, *question, *http_host;
	int			fd, wasdir, permanent;
	size_t			size;
	struct	stat		statbuf;
	const	struct	passwd	*userinfo;
	FILE			*authfile;
#ifdef		WANT_CTYPES
	const	ctypes		*search = NULL;
#endif		/* WANT_CTYPES */

	alarm(240);

	/* Sanitize the requested path */
	question = strchr(params, '?');
	while ((temp = strstr(params, "//")))
		if (!question || (temp < question))
		{
			bcopy(temp + 1, temp, strlen(temp));
			question--;
		}
		else
			break;
	while ((temp = strstr(params, "/./")))
		if (!question || (temp < question))
		{
			bcopy(temp + 2, temp, strlen(temp));
			question -= 2;
		}
		else
			break;

	strncpy(real_path, params, XS_PATH_MAX);
	real_path[XS_PATH_MAX-1] = '\0';
	setprocname("xs: Handling `%s' from `%s'", real_path, remotehost);
	userinfo = NULL;

	if (params[1] == '~')
	{
		if ((temp = strchr(params + 2, '/')))
			*temp = 0;
		if (!(userinfo = getpwnam(params + 2)))
		{
			server_error("404 User is unknown", "USER_UNKNOWN");
			return;
		}
		if (transform_user_dir(base, userinfo, 1))
			return;
		if (!origeuid)
		{
			setegid(userinfo->pw_gid);
			setgroups(1, (const gid_t *)&userinfo->pw_gid);
			seteuid(userinfo->pw_uid);
		}
		if (!geteuid())
		{
			error("500 Effective UID is not valid");
			return;
		}
		if (temp)
		{
			*temp = '/';
			file = temp;
		} else
			file = params + strlen(params);
	} else
	{
		file = params;
#ifdef		SIMPLE_VIRTUAL_HOSTING
		if ((http_host = getenv("HTTP_HOST")))
		{
			strncpy(base, calcpath(http_host), XS_PATH_MAX-1);
			base[XS_PATH_MAX-2] = '\0';
			if (stat(base, &statbuf) || !S_ISDIR(statbuf.st_mode))
				strncpy(base, calcpath(current->htmldir), XS_PATH_MAX-1);
#ifdef		VIRTUAL_UID
			else
			{
				/* We got a virtual host, now set euid */
				if (!origeuid)
				{
					setegid(statbuf.st_gid);
					setgroups(1, (const gid_t *)&statbuf.st_gid);
					seteuid(statbuf.st_uid);
				}
				if (!(geteuid()))
				{
					error("500 Effective UID is not valid");
					return;
				}
			}
#endif		/* VIRTUAL_UID */
		}
		else
#endif		/* SIMPLE_VIRTUAL_HOSTING */
			strncpy(base, calcpath(current->htmldir), XS_PATH_MAX-1);
		base[XS_PATH_MAX-2] = '\0';
		strcat(base, "/");
		if (!origeuid)
		{
			setegid(config.groupid);
			setgroups(1, &config.groupid);
			seteuid(config.userid);
		}
		if (!geteuid())
		{
			error("500 Effective UID is not valid");
			return;
		}
	}
	strncpy(currentdir, base, XS_PATH_MAX);
	currentdir[XS_PATH_MAX-1] = '\0';

	size = strlen(HTTPD_SCRIPT_ROOT);
	if ((*file && (!strncmp(file + 1, HTTPD_SCRIPT_ROOT, size)) &&
		(file[size + 1] == '/')) /* ||
		((file[0] == '/') && ((file[1] == '?') || !file[1] )) */ )
	{
		do_script(params, NULL, headers);
		return;
	}

	RETRY_SCRIPT:
#ifdef		HANDLE_SCRIPT
	search = itype;
	while (search)
	{
		size = strlen(search->ext);
		if ((temp = strstr(file, search->ext)) &&
			(*(temp + size) == '\0' || *(temp + size) == '?'))
		{
			if (!strcmp(search->prog, "internal:404"))
				error("404 Requested URL not found");
			else
				do_script(params, search->prog, headers);
			return;
		}
		search = search->next;
	}
#endif		/* HANDLE_SCRIPT */

	if (postonly)
	{
		server_error("403 Cannot use POST method on non-CGI",
			"POST_ON_NON_CGI");
		return;
	}

	if ((temp = strchr(file, '?')))
	{
		*temp = 0;
		setenv("QUERY_STRING", temp + 1, 1);
		if ((temp = strchr(real_path, '?')))
			*temp = 0;
	}

	if (*file)
		wasdir = (file[strlen(file) - 1] == '/');
	else
		wasdir = 0;
	if (strstr(file, "/..") || strstr(file, "/.xs") || strstr(file, "/.noxs"))
	{
		server_error("403 Invalid path specified", "INVALID_PATH");
		return;
	}

	/* if (*file == '/')
		file++; */
	if ((temp = strrchr(file, '/')))
	{
		*temp = 0;
		size = strlen(base);
		file[XS_PATH_MAX - (temp - file + 1 + size)] = 0;
		strcpy(base + size, file);
		strcat(base + size, "/");
		file = temp + 1;
		*temp = '/';
	}

	if ((!*file) && (wasdir))
		strcat(real_path, filename = INDEX_HTML);
	else
		filename = file;

	RETRY:
	snprintf(total, XS_PATH_MAX, "%s/.xsuid", base);
	total[XS_PATH_MAX-1] = '\0';
	if (!stat(total, &statbuf))
	{
		if (!origeuid)
		{
			seteuid(origeuid);
			setegid(config.groupid);
			setgroups(1, &config.groupid);
			seteuid(config.userid);
		}
		if (!geteuid())
		{
			error("500 Effective UID is not valid");
			return;
		}
	}
	/* Check for directory permissions */
	if (stat(base, &statbuf))
	{
		error("404 Requested URL not found");
		return;
	}
	if (userinfo && (statbuf.st_mode & S_IWGRP) && (statbuf.st_mode & S_IWOTH))
	{
		error("403 User directory is world-writable");
		return;
	}
	if (userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
		error("403 Invalid owner of user directory");
		return;
	}
	
	/* Check for *.redir instructions */
	permanent = 0;
	snprintf(total, XS_PATH_MAX, "%s%s.redir", base, filename);
	total[XS_PATH_MAX-1] = '\0';
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		snprintf(total, XS_PATH_MAX, "%s%s.Redir", base, filename);
		total[XS_PATH_MAX-1] = '\0';
		if ((fd = open(total, O_RDONLY, 0)) >= 0)
			permanent = 1;
	}
	if (fd >= 0)
	{
		if ((size = read(fd, total, MYBUFSIZ)) <= 0)
		{
			error("500 Redirection filename error");
			close(fd); return;
		}
		total[size] = 0;
		strtok(total, "\r\n"); redirect(total, permanent);
		close(fd); return;
	}
	snprintf(total, XS_PATH_MAX, "%s/.redir", base);
	total[XS_PATH_MAX-1] = '\0';
	if ((fd = open(total, O_RDONLY, 0)) >= 0)
	{
		if ((size = read(fd, total, XS_PATH_MAX - strlen(filename) - 16)) <= 0)
		{
			error("500 Directory redirection filename error");
			close(fd); return;
		}
		close(fd);
		temp = total + size; *temp = 0;
		while ((temp > total) && (*(temp - 1) < ' '))
			*(--temp) = 0;
		strcat(total, filename);
		strtok(total, "\r\n"); redirect(total, 0);
		return;
	}
	/* Check for *.noxs permissions */
	snprintf(total, XS_PATH_MAX, "%s/.noxs", base);
	total[XS_PATH_MAX-1] = '\0';
#ifdef		RESTRICTXS
	if (!stat(total, &statbuf) && !allowxs(total))
#else		/* RESTRICTXS */
	if (!stat(total, &statbuf))
#endif		/* RESTRICTXS */
	{
		server_error("403 Directory is not available", "DIR_NOT_AVAIL");
		return;
	}
#ifdef		HANDLE_CHARSET
	/* Check for *.charset preferences */
	snprintf(total, XS_PATH_MAX, "%s%s.charset", base, filename);
	total[XS_PATH_MAX-1] = '\0';
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		snprintf(total, XS_PATH_MAX, "%s.charset", base);
		total[XS_PATH_MAX-1] = '\0';
		fd = open(total, O_RDONLY, 0);
	}
	if (fd >= 0)
	{
		read(fd, charset, XS_PATH_MAX);
		charset[XS_PATH_MAX-1] = '\0';
		if ((temp = strchr(charset, '\n')))
			temp[0] = '\0';
		close(fd);
	}
	else
		charset[0] = '\0';
#endif		/* HANDLE_CHARSET */

	/* Check after redirection */
	snprintf(auth, XS_PATH_MAX, "%s/%s", base, AUTHFILE);
	auth[XS_PATH_MAX-1] = '\0';
	if ((authfile = fopen(auth, "r")))
	{
		if (check_auth(authfile))
			return;
	}

#ifdef		HANDLE_COMPRESSED
	search = NULL;
#endif		/* HANDLE_COMPRESSED */
	snprintf(total, XS_PATH_MAX, "%s%s", base, filename);
	total[XS_PATH_MAX-1] = '\0';
	if (!lstat(total, &statbuf) && S_ISLNK(statbuf.st_mode) &&
		userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
		error("403 Invalid owner of symlink");
		return;
	}
	if (stat(total, &statbuf))
#ifdef		HANDLE_COMPRESSED
	{
		search = ctype;
		temp = total + strlen(total);
		while (search)
		{
			strcpy(temp, search->ext);
			if (!stat(total, &statbuf))
				break;
			search = search->next;
		}
		if (!search)
			goto NOTFOUND;
	}
#else		/* Not HANDLE_COMPRESSED */
		goto NOTFOUND;
#endif		/* HANDLE_COMPRESSED */

	if (!S_ISREG(statbuf.st_mode))
	{
		if (!S_ISDIR(statbuf.st_mode))
		{
			server_error("403 Not a regular filename", "NOT_REGULAR");
			return;
		}
		if (!strcmp(filename, INDEX_HTML) || !strcmp(file, INDEX_HTML_2))
		{
			error("403 The index may not be a directory");
			return;
		}
		if (wasdir)
		{
			wasdir = 0;
			strcat(real_path, filename = INDEX_HTML);
			goto RETRY;
		} else
		{
			http_host = getenv("HTTP_HOST");

			if (question)
			{
				if (strcmp(config.port, "http") && !http_host)
					snprintf(total, XS_PATH_MAX, "http://%s:%s%s/?%s",
						current->hostname, config.port,
						params, question + 1);
				else
					snprintf(total, XS_PATH_MAX, "http://%s%s/?%s",
						(http_host ? http_host : current->hostname),
						params, question + 1);
			}
			else
			{
				if (strcmp(config.port, "http") && !http_host)
					snprintf(total, XS_PATH_MAX, "http://%s:%s%s/",
						current->hostname, config.port, params);
				else
					snprintf(total, XS_PATH_MAX, "http://%s%s/",
						(http_host ? http_host : current->hostname),
						params);
				}
			total[XS_PATH_MAX-1] = '\0';
			redirect(total, 1);
			return;
		}
	}

	modtime = statbuf.st_mtime;
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		server_error("403 File permissions deny access", "PERMISSION");
		return;
	}
	strncpy(name, filename, XS_PATH_MAX);
	name[XS_PATH_MAX-1] = '\0';

#ifdef		HANDLE_COMPRESSED
	if (search)
	{
		if (strlen(search->name) &&
			strstr(getenv("HTTP_ACCEPT_ENCODING"), search->name))
		{
			setenv("CONTENT_ENCODING", search->name, 1);
			senduncompressed(fd);
		}
		else
			sendcompressed(fd, search->prog);
	}
	else
#endif		/* HANDLE_COMPRESSED */
		senduncompressed(fd);
	return;

	NOTFOUND:
	if (!strcmp(filename, INDEX_HTML) && strcmp(INDEX_HTML, INDEX_HTML_2))
	{
		strcpy(real_path + strlen(real_path) - strlen(INDEX_HTML),
			filename = INDEX_HTML_2);
		wasdir = 0;
		goto RETRY;
	}
	else if (!strcmp(filename, INDEX_HTML_2) &&
			strcmp(INDEX_HTML_2, INDEX_HTML_3))
	{
		strcpy(real_path + strlen(real_path) - strlen(INDEX_HTML_2),
			filename = INDEX_HTML_3);
		/* oops, lost the arguments  -  quick hack to get it back */
		if (question)
		{
			strcat(real_path, "?");
			strcat(real_path, question + 1);
		}
		params = file = real_path;
		wasdir = 0;
		goto RETRY_SCRIPT;
	}
	server_error("404 Requested URL not found", "NOT_FOUND");
}

extern	VOID
do_post DECL1(char *, params)
{
	postonly = 1;
	do_get(params);
}

extern	VOID
do_head DECL1(char *, params)
{
	headonly = 1;
	do_get(params);
}

extern	VOID
do_options DECL1(char *, params)
{
	secprintf("%s 200 OK\r\n", version);
	stdheaders(0, 0, 0);
	secprintf("Content-length: 0\r\n");
	secprintf("Allow: GET, HEAD, POST, OPTIONS\r\n\r\n");
	(void)params;
}

extern	VOID
loadfiletypes DECL0
{
	char		line[MYBUFSIZ], *end, *comment;
	const	char	*mimepath;
	FILE		*mime;
	ftypes		*prev, *new;

	while (ftype)
	{
		new = ftype->next;
		free(ftype); ftype = new;
	}
	mimepath = calcpath(MIMETYPESFILE);
	if (!(mime = fopen(mimepath, "r")))
		err(1, "fopen(`%s' [read])", mimepath);
	prev = NULL;
	while (fgets(line, MYBUFSIZ, mime))
	{
		if ((comment = strchr(line, '#')))
			*comment = 0;
		end = line + strlen(line);
		while ((end > line) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (end == line)
			continue;
		if (!(new = (ftypes *)malloc(sizeof(ftypes))))
			errx(1, "Out of memory in loadfiletypes()");
		if (prev)
			prev->next = new;
		else
			ftype = new;
		prev = new; new->next = NULL;
		if (sscanf(line, "%s %s", new->name, new->ext) != 2)
			errx(1, "Unable to parse line `%s' in `%s'",
				line, mimepath);
	}
	fclose(mime);
}

#ifdef		HANDLE_COMPRESSED
extern	VOID
loadcompresstypes DECL0
{
	char		line[MYBUFSIZ], *end, *comment;
	const	char	*path;
	FILE		*methods;
	ctypes		*prev, *new;

	while (ctype)
	{
		new = ctype->next;
		free(ctype); ctype = new;
	}
	path = calcpath(COMPRESS_METHODS);
	if (!(methods = fopen(path, "r")))
		err(1, "fopen(`%s' [read])", path);
	prev = NULL;
	while (fgets(line, MYBUFSIZ, methods))
	{
		if ((comment = strchr(line, '#')))
			*comment = 0;
		end = line + strlen(line);
		while ((end > line) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (line == end)
			continue;
		if (!(new = (ctypes *)malloc(sizeof(ctypes))))
			errx(1, "Out of memory in loadcompresstypes()");
		if (prev)
			prev->next = new;
		else
			ctype = new;
		prev = new; new->next = NULL;
		if (sscanf(line, "%s %s %s", new->prog, new->ext, new->name) != 3 &&
			sscanf(line, "%s %s", new->prog, new->ext) != 2)
			errx(1, "Unable to parse `%s' in `%s'", line, path);
	}
	fclose(methods);
}
#endif		/* HANDLE_COMPRESSED */

#ifdef		HANDLE_SCRIPT
extern	VOID
loadscripttypes DECL0
{
	char		line[MYBUFSIZ], *end, *comment;
	const	char	*path;
	FILE		*methods;
	ctypes		*prev, *new;

	while (itype)
	{
		new = itype->next;
		free(itype); itype = new;
	}
	path = calcpath(SCRIPT_METHODS);
	if (!(methods = fopen(path, "r")))
		err(1, "fopen(`%s' [read])", path);
	prev = NULL;
	while (fgets(line, MYBUFSIZ, methods))
	{
		if ((comment = strchr(line, '#')))
			*comment = 0;
		end = line + strlen(line);
		while ((end > line) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (line == end)
			continue;
#ifndef		HANDLE_PERL
		if (!strncmp(line, "internal:perl", 13))
			continue;
#endif		HANDLE_PERL
		if (!(new = (ctypes *)malloc(sizeof(ctypes))))
			errx(1, "Out of memory in loadscripttypes()");
		if (prev)
			prev->next = new;
		else
			itype = new;
		prev = new; new->next = NULL;
		if (sscanf(line, "%s %s", new->prog, new->ext) != 2)
			errx(1, "Unable to parse `%s' in `%s'", line, path);
	}
	fclose(methods);
}
#endif		/* HANDLE_SCRIPT */

#ifdef		HANDLE_SSL
extern	VOID
loadssl	DECL0
{
	if (config.usessl) {
		SSLeay_add_all_algorithms();
		SSL_load_error_strings();
		ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (!SSL_CTX_use_certificate_file(ssl_ctx, calcpath(CERT_FILE),
				SSL_FILETYPE_PEM) ||
			!SSL_CTX_use_PrivateKey_file(ssl_ctx, calcpath(KEY_FILE),
				SSL_FILETYPE_PEM) ||
			!SSL_CTX_check_private_key(ssl_ctx))
			errx(1, "Cannot initialise SSL");
		ERR_print_errors_fp(stderr);
	}
}
#endif		/* HANDLE_SSL */

#ifdef		HANDLE_PERL
extern	VOID
loadperl	DECL0
{
	char *embedding[] = { "", HTTPD_ROOT "/persistent.pl" };
	char filename [1024];
	int exitstatus = 0;
	STRLEN n_a;

	if (!(perl = perl_alloc()))
	   errx(1, "No memory!");
	perl_construct(perl);

	exitstatus = perl_parse(perl, NULL, 2, embedding, NULL);
	if (!exitstatus)
	   exitstatus = perl_run(perl);
	else
		errx(1, "No perl!");
}
#endif		/* HANDLE_PERL */

extern	int
getfiletype DECL1(int, print)
{
	const	ftypes	*search;
	const	char	*ext;
	char		extension[20];
	int		count;

	if (!(ext = strrchr(name, '.')) || !(*(++ext)))
	{
		if (print)
			secprintf("Content-type: text/plain\r\n");
		return(0);
	}
	for (count = 0; ext[count] && (count < 16); count++)
		extension[count] =
			isupper(ext[count]) ? tolower(ext[count]) : ext[count];
	extension[count] = 0;
	search = ftype;
	while (search)
	{
		if (!strcmp(extension, search->ext))
		{
			if (print)
			{
#ifdef		HANDLE_CHARSET
				if (*charset)
					secprintf("Content-type: %s; charset=%s\r\n",
						search->name, charset);
				else
#endif		/* HANDLE_CHARSET */
					secprintf("Content-type: %s\r\n", search->name);
			}
			return(!strcmp(search->name, "text/html"));
		}
		search = search->next;
	}
	if (print)
		secprintf("Content-type: application/octet-stream\r\n");
	return(0);
}

