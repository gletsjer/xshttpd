/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: methods.c,v 1.118 2004/11/26 16:53:01 johans Exp $ */

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
#ifndef		s6_addr16
#define		s6_addr16	__u6_addr.__u6_addr16
#define		s6_addr32	__u6_addr.__u6_addr32
#endif		/* s6_addr16 */
#ifndef		IN6_ARE_MASKED_ADDR_EQUAL
#define IN6_ARE_MASKED_ADDR_EQUAL(d, a, m)      (       \
	(((d)->s6_addr32[0] ^ (a)->s6_addr32[0]) & (m)->s6_addr32[0]) == 0 && \
	(((d)->s6_addr32[1] ^ (a)->s6_addr32[1]) & (m)->s6_addr32[1]) == 0 && \
	(((d)->s6_addr32[2] ^ (a)->s6_addr32[2]) & (m)->s6_addr32[2]) == 0 && \
	(((d)->s6_addr32[3] ^ (a)->s6_addr32[3]) & (m)->s6_addr32[3]) == 0 )
#endif		/* IN6_ARE_MASKED_ADDR_EQUAL */

#include	"httpd.h"
#include	"methods.h"
#include	"local.h"
#include	"procname.h"
#include	"ssi.h"
#include	"extra.h"
#include	"cgi.h"
#include	"xscrypt.h"
#include	"path.h"
#include	"setenv.h"
#include	"mygetopt.h"
#include	"mystring.h"
#include	"htconfig.h"

#ifndef		NOFORWARDS
static int	getfiletype		PROTO((int));
#ifdef	INET6
static int	v6masktonum		PROTO((int, struct in6_addr *));
#endif	/* INET6 */
static int	allowxs			PROTO((FILE *));
static void	senduncompressed	PROTO((int));
static void	sendcompressed		PROTO((int, const char *));
static FILE *	find_file		PROTO((const char *, const char *, const char *));
#endif		/* NOFORWARDS */

/* Global structures */

typedef	struct	ftypes
{
	struct	ftypes	*next;
	char		name[32], ext[16];
} ftypes;

typedef	struct	ctypes
{
	struct	ctypes	*next;
	char		prog[XS_PATH_MAX], ext[16], name[16];
} ctypes;

static	ftypes	*ftype = NULL, *lftype = NULL;
static	ctypes	*ctype = NULL;
static	ctypes	*itype = NULL, *litype = NULL;
static	char	charset[XS_PATH_MAX];
#ifdef		HANDLE_PERL
static	PerlInterpreter *	perl = NULL;
#endif		/* HANDLE_PERL */

extern	void
senduncompressed(int fd)
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
	if ((size = lseek(fd, (off_t)0, SEEK_END)) == -1)
	{
		error("500 Cannot lseek() to end of file");
		close(fd);
		return;
	}
	if (lseek(fd, (off_t)0, SEEK_SET))
	{
		error("500 Cannot lseek() to beginning of file");
		close(fd);
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
			lseek(fd, (off_t)0, SEEK_SET);
		}
#endif		/* WANT_SSI */
		if ((env = getenv("IF_MODIFIED_SINCE")))
		{
			strptime(env, "%a, %d %b %Y %H:%M:%S", &reqtime);
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
			strptime(env, "%a, %d %b %Y %H:%M:%S", &reqtime);
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
		if (!dynamic)
		{
			strftime(modified, sizeof(modified),
				"%a, %d %b %Y %H:%M:%S GMT", gmtime(&modtime));
			secprintf("Last-modified: %s\r\n\r\n", modified);
		}
		else
			secprintf("\r\n");
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
		(void) munmap(buffer, size);
		size = written;
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

extern	void
sendcompressed(int fd, const char *method)
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
			close(fd);
			return;
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
		(void) execl(method, method, NULL);
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

#ifdef		INET6
static	int
v6masktonum(int mask, struct in6_addr *addr6)
{
	int		x, y, z;

	for (x = 0; x < 4; x++)
		addr6->s6_addr32[x] = 0;

	y = 0;
	z = 0;
	for (x = 0; x < mask; x++)
	{
		addr6->s6_addr[y] |= (1 << (7 - z));
		z++;
		if (z == 8)
		{
			z = 0;
			y++;
		}
	}

	return 0;
}
#endif		/* INET6 */

extern	int
allowxs(FILE *rfile)
{
	char	*remoteaddr, *slash;
	char	allowhost[256];

	if (!config.userestrictaddr)
		return 1; /* always allowed */
	if (!(remoteaddr = getenv("REMOTE_ADDR")))
		return 0; /* access denied */

	while (fgets(allowhost, 256, rfile))
	{
		allowhost[255] = '\0';
		if (strlen(allowhost) &&
			allowhost[strlen(allowhost) - 1] == '\n')
		    allowhost[strlen(allowhost) - 1] = '\0';

		/* allow host if prefix(remote_host) matches host/IP in file */
		if (strlen(allowhost) &&
			!strncmp(remoteaddr, allowhost, strlen(allowhost)))
		{
			fclose(rfile);
			return 1; /* access granted */
		}

		/* allow host if remote_addr matches CIDR subnet in file */
		if ((slash = strchr(allowhost, '/')) &&
			strchr(allowhost, '.') &&
			strchr(remoteaddr, '.'))
		{
			struct	in_addr		allow, remote;
			unsigned int		subnet;

			*slash = '\0';
			if ((subnet = atoi(slash + 1)) > 32)
				subnet = 32;
			inet_aton(remoteaddr, &remote);
			inet_aton(allowhost, &allow);

#define	IPMASK(addr, sub) (addr.s_addr & htonl(~((1 << (32 - subnet)) - 1)))
			if (IPMASK(remote, subnet) == IPMASK(allow, subnet))
				return 1;
		}
#ifdef		INET6
		if ((slash = strchr(allowhost, '/')) &&
			strchr(allowhost, ':') &&
			strchr(remoteaddr, ':'))
		{
			struct	in6_addr	allow, remote, mask;
			unsigned int		subnet;

			*slash = '\0';
			if ((subnet = atoi(slash + 1)) > 128)
				subnet = 128;
			inet_pton(AF_INET6, remoteaddr, &remote);
			inet_pton(AF_INET6, allowhost, &allow);
			v6masktonum(subnet, &mask);
			if (IN6_ARE_MASKED_ADDR_EQUAL(&remote, &allow, &mask))
				return 1;
		}
#endif		/* INET6 */

		/* allow any host if the local port matches :port in .noxs */
#ifdef		HAVE_GETADDRINFO
		if (strlen(allowhost) > 1 && ':' == allowhost[0])
		{
			int cport = atoi(allowhost + 1);
			int lport = atoi(getenv("SERVER_PORT"));
			struct	addrinfo	hints, *res;

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			if (!cport)
			{
				if ((getaddrinfo(NULL, allowhost + 1, &hints, &res)))
					continue;
				cport = htons(res->ai_family == AF_INET6
					? ((struct sockaddr_in6 *)res->ai_addr)->sin6_port
					: ((struct sockaddr_in *)res->ai_addr)->sin_port);
				freeaddrinfo(res);
			}
			if (lport && cport == lport)
			{
				fclose(rfile);
				return 1; /* access granted */
			}
		}
#endif		/* HAVE_GETADDRINFO */
	}

	fclose(rfile);
	return 0;
}

static	FILE	*
find_file(const char *orgbase, const char *base, const char *file)
{
	char		path[XS_PATH_MAX], *p;
	FILE		*fd;
	size_t		len = strlen(orgbase);

	/* Check after redirection */
	/* Ugly way to do this recursively */
	snprintf(path, XS_PATH_MAX, "%s/", base);
	for (p = path;
		(p == path || !strncmp(orgbase, path, len)) &&
		(p = strrchr(path, '/'));
		*p = '\0')
	{
		snprintf(p, XS_PATH_MAX - (p - path), "/%s", file);
		path[XS_PATH_MAX-1] = '\0';
		if ((fd = fopen(path, "r")))
			return fd;
	}

	return NULL;
}

extern	void
do_get(char *params)
{
	char			*temp, *file, *cgi, *question,
			base[XS_PATH_MAX], orgbase[XS_PATH_MAX],
			total[XS_PATH_MAX], temppath[XS_PATH_MAX];
	const	char		*filename, *http_host;
	int			fd, wasdir, permanent, script = 0, tmp;
	size_t			size;
	struct	stat		statbuf;
	const	struct	passwd	*userinfo;
	FILE			*authfile;
	const	ctypes		*csearch = NULL, *isearch = NULL;

	alarm(240);

	/* Sanitize the requested path */
	question = strchr(params, '?');
	while ((temp = strstr(params, "//")))
		if (!question || (temp < question))
		{
			bcopy(temp + 1, temp, strlen(temp));
			if (question)
				question--;
		}
		else
			break;
	while ((temp = strstr(params, "/./")))
		if (!question || (temp < question))
		{
			bcopy(temp + 2, temp, strlen(temp));
			if (question)
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
	}
	else
	{
		file = params;
		*base = 0;
		if (config.usevirtualhost &&
			current == config.system &&
			(http_host = getenv("HTTP_HOST")))
		{
			if (config.virtualhostdir)
				snprintf(base, XS_PATH_MAX, "%s/%s",
					calcpath(config.virtualhostdir),
					http_host);
			else
				strncpy(base, calcpath(http_host),
					XS_PATH_MAX-1);
			base[XS_PATH_MAX-2] = '\0';
			if (stat(base, &statbuf) || !S_ISDIR(statbuf.st_mode))
				*base = '\0';
			else if (config.usevirtualuid)
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
		}
		if (!*base)
		{
			size = strlen(current->execdir);
			if (!strncmp(params + 1, current->execdir, size))
			{
				script = 1;
				file += size + 2;
				strncpy(base, calcpath(current->phexecdir), XS_PATH_MAX-1);
			}
			else
				strncpy(base, calcpath(current->htmldir), XS_PATH_MAX-1);
		}
		base[XS_PATH_MAX-2] = '\0';
		strcat(base, "/");

		if (config.usevirtualuid && current->userid && current->groupid)
		{
			setegid(current->groupid);
			setgroups(1, (const gid_t *)&current->groupid);
			seteuid(current->userid);
		}
		else if (!origeuid)
		{
			setegid(config.system->groupid);
			setgroups(1, &config.system->groupid);
			seteuid(config.system->userid);
		}
		if (!geteuid())
		{
			error("500 Effective UID is not valid");
			return;
		}
	}
	strncpy(orgbase, base, XS_PATH_MAX);

	if (question)
	{
		setenv("QUERY_STRING", question + 1, 1);
		*question = 0;
	}

	if (*file)
		wasdir = (file[strlen(file) - 1] == '/');
	else
		wasdir = 0;
	if (strstr(file, "/..") || strstr(file, "/.xs") || strstr(file, "/.noxs") || strstr(file, ".redir") || strstr(file, ".Redir") || strstr(file, ".charset"))
	{
		server_error("403 Invalid path specified", "INVALID_PATH");
		return;
	}

	if (*file == '/' && file[1] != '\0')
		file++;
	cgi = file;

	/* look for file on disk */
	snprintf(temppath, XS_PATH_MAX, "%s%s", base, file);
	if (!wasdir &&
		!stat(temppath, &statbuf) &&
		(statbuf.st_mode & S_IFMT) == S_IFREG)
	{
		/* No PATH_INFO for regular files */
#if		0
		setenv("PATH_INFO", params, 1);
		if (!getenv("ORIG_PATH_INFO"))
			setenv("ORIG_PATH_INFO", params, 1);
		setenv("PATH_TRANSLATED", temppath, 1);
#endif		/* 0 */
		if (!getenv("ORIG_PATH_TRANSLATED"))
			setenv("ORIG_PATH_TRANSLATED", temppath, 1);
		setenv("SCRIPT_FILENAME", temppath, 1);
	}
	else
	{
		temp = file;
		while ((temp = strchr(temp, '/')))
		{
			char fullpath[XS_PATH_MAX];
			*temp = 0;
			snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);
			if (stat(fullpath, &statbuf))
				break; /* error later */
			if ((statbuf.st_mode & S_IFMT) == S_IFREG)
			{
				*temp = '/';
				setenv("PATH_INFO", temp, 1);
				snprintf(temppath, XS_PATH_MAX, "%s%s", fullpath, temp);
				setenv("PATH_TRANSLATED", temppath, 1);
				setenv("SCRIPT_FILENAME", temppath, 1);
				*temp = 0;
				break;
			}
			*(temp++) = '/';
		}
	}

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
	strncpy(currentdir, base, XS_PATH_MAX);
	currentdir[XS_PATH_MAX-1] = '\0';

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
			setegid(config.system->groupid);
			setgroups(1, &config.system->groupid);
			seteuid(config.system->userid);
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
#if 0
		error("403 Invalid owner of user directory");
		return;
#endif
	}
	
	/* Check for *.noxs permissions */
	if ((authfile = find_file(orgbase, base, ".noxs")) &&
		!allowxs(authfile))
	{
		server_error("403 Directory is not available", "DIR_NOT_AVAIL");
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
			close(fd);
			return;
		}
		total[size] = 0;
		(void) strtok(total, "\r\n");
		redirect(total, permanent);
		close(fd);
		return;
	}
	snprintf(total, XS_PATH_MAX, "%s/.redir", base);
	total[XS_PATH_MAX-1] = '\0';
	if ((fd = open(total, O_RDONLY, 0)) >= 0)
	{
		if ((size = read(fd, total, XS_PATH_MAX - strlen(filename) - 16)) <= 0)
		{
			error("500 Directory redirection filename error");
			close(fd);
			return;
		}
		close(fd);
		temp = total + size; *temp = 0;
		while ((temp > total) && (*(temp - 1) < ' '))
			*(--temp) = 0;
		strcat(total, filename);
		strtok(total, "\r\n"); redirect(total, 0);
		return;
	}
	charset[0] = '\0';
	if (config.usecharset)
	{
		FILE		*charfile;

		/* Check for *.charset preferences */
		snprintf(total, XS_PATH_MAX, "%s%s.charset", base, filename);
		total[XS_PATH_MAX-1] = '\0';
		if ((charfile = fopen(total, "r")) ||
			(charfile = find_file(orgbase, base, ".charset")))
		{
			if (!fread(charset, 1, XS_PATH_MAX, charfile))
				charset[0] = '\0';
			else
				charset[XS_PATH_MAX-1] = '\0';
			if ((temp = strchr(charset, '\n')))
				temp[0] = '\0';
			fclose(charfile);
		}
	}

	if ((authfile = find_file(orgbase, base, AUTHFILE)) &&
		check_auth(authfile))
	{
		return;
	}

	snprintf(total, XS_PATH_MAX, "%s%s", base, filename);
	total[XS_PATH_MAX-1] = '\0';
	if (!lstat(total, &statbuf) && S_ISLNK(statbuf.st_mode) &&
		userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
		error("403 Invalid owner of symlink");
		return;
	}
	if (stat(total, &statbuf))
	{
		if (config.usecompressed)
		{
			csearch = ctype;
			temp = total + strlen(total);
			while (csearch)
			{
				strcpy(temp, csearch->ext);
				if (!stat(total, &statbuf))
					break;
				csearch = csearch->next;
			}
			if (!csearch)
				goto NOTFOUND;
		}
		else
			goto NOTFOUND;
	}

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
	if (userinfo &&
		(statbuf.st_mode & (S_IWGRP | S_IWOTH)) &&
		(statbuf.st_mode & S_IXUSR))
	{
		error("403 User executable can be written by others");
		return;
	}

	modtime = statbuf.st_mtime;
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		server_error("403 File permissions deny access", "PERMISSION");
		return;
	}
	strncpy(name, filename, XS_PATH_MAX);
	name[XS_PATH_MAX-1] = '\0';

	/* check for local file type */
	loadfiletypes(orgbase, base);

	/* check litype for local and itype for global settings */
	if ((tmp = config.uselocalscript))
		loadscripttypes(orgbase, base);
	for (isearch = litype ? litype : itype; isearch; isearch = isearch->next)
	{
		size = strlen(isearch->ext);
		if ((temp = strstr(filename, isearch->ext)) &&
			strlen(temp) == strlen(isearch->ext))
		{
			if (!strcmp(isearch->prog, "internal:404"))
				error("404 Requested URL not found");
			else if (!strcmp(isearch->prog, "internal:text"))
			{
				script = -1;
				break;
			}
			else if (!strcmp(isearch->prog, "internal:exec"))
				do_script(params, base, filename, NULL, headers);
			else
				do_script(params, base, filename, isearch->prog, headers);
			return;
		}
		/* hack to browse global itype after local litype */
		if (!isearch->next && tmp && litype)
		{
			tmp = 0;
			isearch = itype;
		}
	}

	/* Do this only after all the security checks */
	if (script >= 0)
	{
		size = strlen(current->execdir);
		if (script ||
			(*cgi && !strncmp(cgi, current->execdir, size) && cgi[size] == '/'))
		{
			close(fd);
			do_script(params, base, file, NULL, headers);
			return;
		}
	}

	if (postonly)
	{
		server_error("403 Cannot use POST method on non-CGI",
			"POST_ON_NON_CGI");
		close(fd);
		return;
	}

	if (config.usecompressed && csearch)
	{
		if (strlen(csearch->name) &&
			(temp = getenv("HTTP_ACCEPT_ENCODING")) &&
			strstr(temp, csearch->name))
		{
			setenv("CONTENT_ENCODING", csearch->name, 1);
			senduncompressed(fd);
		}
		else
			sendcompressed(fd, csearch->prog);
	}
	else
		senduncompressed(fd);
	return;

	NOTFOUND:
	if ((temp = strchr(real_path, '?')))
		*temp = '\0';
	if (!strcmp(filename, INDEX_HTML) && strcmp(INDEX_HTML, INDEX_HTML_2))
	{
		strcpy(real_path + strlen(real_path) - strlen(INDEX_HTML),
			filename = INDEX_HTML_2);
	}
	else if (!strcmp(filename, INDEX_HTML_2) &&
			strcmp(INDEX_HTML_2, INDEX_HTML_3))
	{
		strcpy(real_path + strlen(real_path) - strlen(INDEX_HTML_2),
			filename = INDEX_HTML_3);
		filename = INDEX_HTML_3;
		snprintf(file, XS_PATH_MAX, "/%s", INDEX_HTML_3);
	}
	else
	{
		/* no more retries */
		server_error("404 Requested URL not found", "NOT_FOUND");
		return;
	}

	/* add original arguments back to real_path */
	if (question)
	{
		strcat(real_path, "?");
		strcat(real_path, question + 1);
	}
	params = real_path;
	wasdir = 0;
	goto RETRY;
}

extern	void
do_post(char *params)
{
	postonly = 1;
	do_get(params);
}

extern	void
do_head(char *params)
{
	headonly = 1;
	do_get(params);
}

extern	void
do_options(const char *params)
{
	secprintf("%s 200 OK\r\n", version);
	stdheaders(0, 0, 0);
	secprintf("Content-length: 0\r\n");
	secprintf("Allow: GET, HEAD, POST, OPTIONS\r\n\r\n");
	(void)params;
}

extern	void
loadfiletypes(char *orgbase, char *base)
{
	char		line[MYBUFSIZ], *end, *comment;
	const char	*mimepath;
	FILE		*mime;
	ftypes		*prev = NULL, *new = NULL;

	if (!base)
	{
		while (ftype)
		{
			new = ftype->next;
			free(ftype); ftype = new;
		}
	}
	while (lftype)
	{
		new = lftype->next;
		free(lftype); lftype = new;
	}
	lftype = NULL;
	if (base)
	{
		mimepath = NULL;
		if (!(mime = find_file(orgbase, base, ".mimetypes")))
			return;
	}
	else
	{
		mimepath = calcpath(MIMETYPESFILE);
		if (!(mime = fopen(mimepath, "r")))
			err(1, "fopen(`%s' [read])", mimepath);
	}
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
		else if (base)
			lftype = new;
		else
			ftype = new;
		prev = new; new->next = NULL;
		if (sscanf(line, "%s %s", new->name, new->ext) != 2)
			errx(1, "Unable to parse line `%s' in `%s'",
				line, mimepath ? mimepath : "local .mimetypes");
	}
	if (lftype && ftype)
		new->next = ftype;
	fclose(mime);
}

extern	void
loadcompresstypes()
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

extern	void
loadscripttypes(char *orgbase, char *base)
{
	char		line[MYBUFSIZ], *end, *comment, *path;
	FILE		*methods;
	ctypes		*prev, *new;

	if (orgbase && base)
	{
		while (litype)
			{ new = litype->next; free(litype); litype = new; }
		path = (char *)malloc(strlen(base) + 12);
		if (!(methods = find_file(orgbase, base, ".xsscripts")))
		{
			free(path);
			return;
		}
	}
	else
	{
		while (itype)
			{ new = itype->next; free(itype); itype = new; }
		path = strdup(calcpath(SCRIPT_METHODS));
		if (!(methods = fopen(path, "r")))
		{
			/* missing script.methods is not fatal */
			free(path);
			return;
		}
	}
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
#endif		/* HANDLE_PERL */
		if (!(new = (ctypes *)malloc(sizeof(ctypes))))
			errx(1, "Out of memory in loadscripttypes()");
		if (prev)
			prev->next = new;
		else if (base)
			litype = new;
		else
			itype = new;
		prev = new; new->next = NULL;
		if (sscanf(line, "%s %s", new->prog, new->ext) != 2)
			errx(1, "Unable to parse `%s' in `%s'", line, path);
	}
	free(path);
	fclose(methods);
}

#ifdef		HANDLE_SSL
extern	void
loadssl()
{
	if (config.usessl) {
		SSLeay_add_all_algorithms();
		SSL_load_error_strings();
		ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (!SSL_CTX_use_certificate_file(ssl_ctx,
				calcpath(config.sslcertificate),
				SSL_FILETYPE_PEM) ||
			!SSL_CTX_use_PrivateKey_file(ssl_ctx,
				calcpath(config.sslprivatekey),
				SSL_FILETYPE_PEM) ||
			!SSL_CTX_check_private_key(ssl_ctx))
			errx(1, "Cannot initialise SSL %s %s",
				calcpath(config.sslcertificate),
				calcpath(config.sslprivatekey));
		ERR_print_errors_fp(stderr);
	}
}
#endif		/* HANDLE_SSL */

#ifdef		HANDLE_PERL
extern	void
loadperl()
{
	const char *embedding[] = { "", HTTPD_ROOT "/persistent.pl" };
	int exitstatus = 0;

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
getfiletype(int print)
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
	search = lftype ? lftype : ftype;
	while (search)
	{
		if (!strcmp(extension, search->ext))
		{
			if (print)
			{
				if (*charset)
					secprintf("Content-type: %s; "
							"charset=%s\r\n",
						search->name, charset);
				else if (!strncmp(search->name, "text/", 5))
					secprintf("Content-type: %s; "
							"charset=%s\r\n",
						search->name,
						config.defaultcharset
						? config.defaultcharset
						: "us-ascii");
				else
					secprintf("Content-type: %s\r\n",
						search->name);
			}
			return !strcmp(search->name, "text/html");

		}
		search = search->next;
	}
	if (print)
		secprintf("Content-type: application/octet-stream\r\n");
	return(0);
}

