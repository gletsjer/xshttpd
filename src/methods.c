/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: methods.c,v 1.200 2007/03/14 23:21:04 johans Exp $ */

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
#ifdef		HAVE_CURL
#include	<curl/curl.h>
#endif		/* HAVE_CURL */
#ifndef		s6_addr32
#define		s6_addr32	__u6_addr.__u6_addr32
#endif		/* s6_addr32 */
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
#include	"ssi.h"
#include	"ssl.h"
#include	"extra.h"
#include	"cgi.h"
#include	"fcgi.h"
#include	"xscrypt.h"
#include	"path.h"
#include	"htconfig.h"
#include	"pcre.h"
#include	"authenticate.h"

static int	getfiletype		(int);
#ifdef	INET6
static int	v6masktonum		(int, struct in6_addr *);
#endif	/* INET6 */
static void	senduncompressed	(int);
static void	sendcompressed		(int, const char *);
static FILE *	find_file		(const char *, const char *, const char *);
static int	check_file_redirect	(const char *, const char *);
static int	check_allow_host	(const char *, char *);
static int	check_noxs		(FILE *);
static int	check_redirect		(FILE *, const char *);
static int	check_location		(FILE *, const char *);
#ifdef		HAVE_CURL
static size_t	curl_readhack		(void *, size_t, size_t, FILE *);
#endif		/* HAVE_CURL */

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
static	ctypes	*itype = NULL, *litype = NULL, *ditype = NULL;
static	ctypes	**isearches[] = { &litype, &itype, &ditype };
static	char	charset[XS_PATH_MAX], mimetype[XS_PATH_MAX],
		scripttype[XS_PATH_MAX],
		language[XS_PATH_MAX], encoding[XS_PATH_MAX],
		p3pref[XS_PATH_MAX], p3pcp[XS_PATH_MAX];
#ifdef		HAVE_CURL
static	size_t	curl_readlen;
#endif		/* HAVE_CURL */
#ifdef		HANDLE_PERL
PerlInterpreter *	my_perl = NULL;
#endif		/* HANDLE_PERL */

static void
senduncompressed(int fd)
{
#ifdef		WANT_SSI
	int		errval;
#endif		/* WANT_SSI */
#ifndef		HAVE_MMAP
	size_t		secreadtotal, writetotal;
#endif		/* HAVE_MMAP */
	int		written, dynamic = 0;
	off_t		size;
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

#ifdef		WANT_SSI
		/* This is extra overhead, overhead, overhead! */
		if (getfiletype(0))
		{
			char input[RWBUFSIZE];

			/* fgets is better: read() may split HTML tags! */
			while (read(fd, input, RWBUFSIZE))
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
				secprintf("%s 304 Not modified\r\n", httpver);
			}
			else
				secprintf("%s 200 OK\r\n", httpver);
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
				secprintf("%s 200 OK\r\n", httpver);
		}
		else
			secprintf("%s 200 OK\r\n", httpver);
		stdheaders(0, 0, 0);
		getfiletype(1);
		if (dynamic)
		{
			if (headers >= 11)
			{
				secprintf("Cache-control: no-cache\r\n");
				secputs("Transfer-encoding: chunked\r\n");
			}
			else
				secprintf("Pragma: no-cache\r\n");
		}
		else
		{
			secprintf("Content-length: %lu\r\n", size);
			strftime(modified, sizeof(modified),
				"%a, %d %b %Y %H:%M:%S GMT", gmtime(&modtime));
			secprintf("Last-modified: %s\r\n", modified);
		}

		if (*encoding)
			secprintf("Content-encoding: %s\r\n", encoding);

		if (*language)
			secprintf("Content-language: %s\r\n", language);

		if (*p3pref && *p3pcp)
			secprintf("P3P: policyref=\"%s\", CP=\"%s\"\r\n",
				p3pref, p3pcp);
		else if (*p3pref)
			secprintf("P3P: policy-ref=\"%s\"\r\n", p3pref);
		else if (*p3pcp)
			secprintf("P3P: CP=\"%s\"\r\n", p3pcp);

		secprintf("\r\n");
	}

	if (headonly)
		goto DONE;

	UNPARSED:
#ifdef		WANT_SSI
	if (!dynamic)
#endif		/* WANT_SSI */
#ifdef		HAVE_MMAP
	{
		char		*buffer;

		if ((buffer = (char *)mmap((caddr_t)0, (size_t)size, PROT_READ,
			MAP_SHARED, fd, (off_t)0)) == (char *)-1)
			err(1, "[%s] httpd: mmap() failed", currenttime);
		alarm((size / MINBYTESPERSEC) + 20);
		fflush(stdout);
		if ((written = secwrite(buffer, (size_t)size)) != size)
		{
			if (written != -1)
				warn("[%s] httpd: Aborted for `%s' (%ld of %ld bytes sent)",
					currenttime,
					remotehost[0] ? remotehost : "(none)",
					(long)written, (long)size);
			else
				warn("[%s] httpd: Aborted for `%s'",
					currenttime,
					remotehost[0] ? remotehost : "(none)");
		}
		(void) munmap(buffer, (size_t)size);
		size = written;
		alarm(0);
	}
#else		/* Not HAVE_MMAP */
	{
		char		buffer[RWBUFSIZE];

		writetotal = 0;
		alarm((size / MINBYTESPERSEC) + 20);
		fflush(stdout);
		while ((secreadtotal = secread(fd, buffer, RWBUFSIZE)) > 0)
		{
			if ((written = secwrite(fileno(stdout), buffer,
				secreadtotal)) != secreadtotal)
			{
				warn("[%s] httpd: Aborted for `%s' (No mmap) (%ld of %ld bytes sent)",
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
	else /* dynamic content only */
	{
		size_t		usize = 0;

		if (headers >= 11)
			chunked = 1;
		alarm((size / MINBYTESPERSEC) + 60);
		errval = sendwithdirectives(fd, (size_t *)&usize);
		if (usize)
			size = (int)usize;
		close(fd);
		switch(errval)
		{
		case ERR_QUIT:
			warnx("[%s] httpd: Aborted for `%s' (ERR_QUIT)",
				currenttime,
				remotehost[0] ? remotehost : "(none)");
			break;
		case ERR_CONT:
			goto UNPARSED;
		default:
			break;
		}
	}
#endif		/* WANT_SSI */

	DONE:
	logrequest(real_path, size);
	close(fd);
}

static void
sendcompressed(int fd, const char *method)
{
	pid_t		pid;
	int		processed;
	char	prefix[] = TEMPORARYPREFIX;
	size_t		count;

#ifdef		HAVE_MKSTEMP
	if (!(processed = mkstemp(prefix)))
	{
		error("500 Unable to open temporary file");
		err(1, "[%s] httpd: Cannot create temporary file", currenttime);
	}
	remove(prefix);
#else		/* HAVE_MKSTEMP */
	char		*tmp;

	/* Removed obsolete tempnam() call
	 * if (!(tmp = tempnam(TEMPORARYPATH, "xs-www")))
	 */
	{
		unsigned int	len = 32 + strlen(TEMPORARYPREFIX);
		if (!(tmp = (char *)malloc(len)))
		{
			error("500 Out of memory in sendcompressed()");
			close(fd);
			return;
		}
		snprintf(tmp, len, "%s.%016ld",
			TEMPORARYPREFIX, (long)getpid());
	}
	remove(tmp);
	if ((processed = open(tmp, O_CREAT | O_TRUNC | O_RDWR | O_EXCL,
		S_IWUSR | S_IRUSR )) < 0)
	{
		error("500 Unable to open temporary file");
		err(1, "[%s] httpd: Cannot open(`%s')", currenttime, tmp);
	}
	remove(tmp); free(tmp); fflush(stdout);
#endif		/* HAVE_MKSTEMP */
	switch(pid = fork())
	{
	case -1:
		warn("[%s] httpd: Cannot fork()", currenttime);
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
		/* So what is a good guess about # open FDs? */
		for (count = 3; count < 1024; count++)
			close(count);
		(void) execl(method, method, NULL);
		error("500 Cannot start conversion program");
		err(1, "[%s] httpd: Cannot execl(`%s')", currenttime, method);
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

static int
check_allow_host(const char *hostname, char *pattern)
{
	char	*slash;

	/* return 1 if pattern matches - i.e. access granted */
	if (!hostname || !pattern || !*hostname || !*pattern)
		return 0;
	
	/* substring match */
	if (!strncmp(hostname, pattern, strlen(pattern)))
		return 1;

	/* allow host if remote_addr matches CIDR subnet in file */
	if ((slash = strchr(pattern, '/')) &&
		strchr(hostname, '.') &&
		strchr(pattern, '.'))
	{
		struct	in_addr		allow, remote;
		unsigned int		subnet;

		*slash = '\0';
		if ((subnet = atoi(slash + 1)) > 32)
			subnet = 32;
		inet_aton(hostname, &remote);
		inet_aton(pattern, &allow);

#define	IPMASK(addr, sub) (addr.s_addr & htonl(~((1 << (32 - subnet)) - 1)))
		if (IPMASK(remote, subnet) == IPMASK(allow, subnet))
			return 1;
	}
#ifdef		INET6
	if ((slash = strchr(pattern, '/')) &&
		strchr(pattern, ':') &&
		strchr(hostname, ':'))
	{
		struct	in6_addr	allow, remote, mask;
		unsigned int		subnet;

		*slash = '\0';
		if ((subnet = atoi(slash + 1)) > 128)
			subnet = 128;
		inet_pton(AF_INET6, hostname, &remote);
		inet_pton(AF_INET6, pattern, &allow);
		v6masktonum(subnet, &mask);
		if (IN6_ARE_MASKED_ADDR_EQUAL(&remote, &allow, &mask))
			return 1;
	}
#endif		/* INET6 */

	/* allow any host if the local port matches :port in .noxs */
#ifdef		HAVE_GETADDRINFO
	if (':' == pattern[0])
	{
		int cport = atoi(hostname + 1);
		int lport = atoi(getenv("SERVER_PORT"));
		struct	addrinfo	hints, *res;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if (!cport && !getaddrinfo(NULL, pattern + 1, &hints, &res))
		{
			cport = htons(res->ai_family == AF_INET6
				? ((struct sockaddr_in6 *)res->ai_addr)->sin6_port
				: ((struct sockaddr_in *)res->ai_addr)->sin_port);
			freeaddrinfo(res);
		}
		if (lport && cport == lport)
			return 1; /* access granted */
	}
#endif		/* HAVE_GETADDRINFO */
	return 0;
}

static int
check_noxs(FILE *rfile)
{
	char	*remoteaddr;
	char	allowhost[256];

	if (!(remoteaddr = getenv("REMOTE_ADDR")))
	{
		server_error("403 File is not available", "NOT_AVAILABLE");
		return 1; /* access denied */
	}

	while (fgets(allowhost, 256, rfile))
	{
		if (strlen(allowhost) &&
			allowhost[strlen(allowhost) - 1] == '\n')
		    allowhost[strlen(allowhost) - 1] = '\0';

		if (!allowhost[0] || '#' == allowhost[0])
			continue;

		if (check_allow_host(remoteaddr, allowhost))
		{
			fclose(rfile);
			return 0; /* access granted */
		}
	}

	fclose(rfile);
	server_error("403 File is not available", "NOT_AVAILABLE");
	return 1;
}

static int
check_location(FILE *fp, const char *filename)
{
	char	line[LINEBUFSIZE];
	char    *p, *name, *value;
	int		state = 0;
	int		restrictcheck = 0, restrictallow = 0;
	FILE    *authfile;

	while (fgets(line, LINEBUFSIZE, fp))
	{
		p = line;
		while ((name = strsep(&p, " \t\r\n")) && !*name)
			/* continue */;

		/* skip comments and blank lines */
		if (!name || !*name || '#' == *name)
			continue;

		/* try to isolate a [url] section */
		if ('[' == name[0])
		{
			for (p = ++name; *p && *p != ']'; p++)
				/* skip */;
			if (!*p)
				/* [ without ]; skip it */
				continue;
			*p = '\0';

			/* always reset the state */
			state = 0;

			/* try simple matching */
			if (fnmatch(name, filename, 0) != FNM_NOMATCH)
				state = 1;
			continue;
		}

		/* ignore anything else if no match */
		if (!state)
			continue;

		while ((value = strsep(&p, " \t\r\n")) && !*value)
			/* continue */;

		/* AuthFilename => $file does .xsauth-type authentication */
		if (!strcasecmp(name, "AuthFilename") ||
			!strcasecmp(name, "AuthFile"))
		{
			if (value && (authfile = fopen(value, "r")))
			{
				/* return if authentication fails
				 * process other directives on success
				 */
				if (check_auth(authfile))
				{
					/* a 401 response has been sent */
					fclose(authfile);
					fclose(fp);
					return 1;
				}
				else
				{
					fclose(authfile);
				}
			}
			else
			{
				server_error("403 Authentication data not available",
					"NOT_AVAILABLE");
				fclose(fp);
				return 1;
			}
		}
		else if (!strcasecmp(name, "Restrict"))
		{
			const char	*remoteaddr = getenv("REMOTE_ADDR");

			restrictcheck = 1;
			if (remoteaddr && *value)
				restrictallow |= check_allow_host(remoteaddr, value);
		}
		else if (!strcasecmp(name, "MimeType"))
			strlcpy(mimetype, value, XS_PATH_MAX);
		else if (!strcasecmp(name, "Execute"))
			strlcpy(scripttype, value, XS_PATH_MAX);
		else if (!strcasecmp(name, "Charset"))
			strlcpy(charset, value, XS_PATH_MAX);
		else if (!strcasecmp(name, "Language"))
			strlcpy(language, value, XS_PATH_MAX);
		else if (!strcasecmp(name, "p3pReference"))
			strlcpy(p3pref, value, XS_PATH_MAX);
		else if (!strcasecmp(name, "p3pCompactPolicy"))
			strlcpy(p3pcp, value, XS_PATH_MAX);
		else if (!strcasecmp(name, "ScriptTimeout"))
			config.scripttimeout = atoi(value);

		/* ... and much more ... */
	}

	fclose(fp);
	if (restrictcheck && !restrictallow)
	{
		server_error("403 File is not available", "NOT_AVAILABLE");
		return 1;
	}

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
		snprintf(p, (size_t)(XS_PATH_MAX - (p - path)), "/%s", file);
		if ((fd = fopen(path, "r")))
			return fd;
	}

	return NULL;
}

void
do_get(char *params)
{
	char			*temp, *file, *cgi, *question,
				base[XS_PATH_MAX], orgbase[XS_PATH_MAX],
				total[XS_PATH_MAX], temppath[XS_PATH_MAX];
	const	char		*filename, *http_host;
	int			fd, wasdir,
				delay_redir = 0, script = 0;
	unsigned int		i;
	size_t			size;
	struct	stat		statbuf;
	const	struct	passwd	*userinfo;
	FILE			*xsfile, *charfile;
	const	ctypes		*csearch = NULL, *isearch = NULL;

	alarm(240);

	/* Sanitize the requested path */
	question = strchr(params, '?');
	while ((temp = strstr(params, "//")))
		if (!question || (temp < question))
		{
			delay_redir = 1;
			memmove(temp, temp + 1, strlen(temp));
			if (question)
				question--;
		}
		else
			break;
	while ((temp = strstr(params, "/./")))
		if (!question || (temp < question))
		{
			delay_redir = 1;
			memmove(temp, temp + 2, strlen(temp) - 1);
			if (question)
				question -= 2;
		}
		else
			break;

	strlcpy(real_path, params, XS_PATH_MAX);
	setproctitle("xs: Handling `%s' from `%s'", real_path, remotehost);
	userinfo = NULL;

	if (!origeuid)
		seteuid(origeuid);

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
		setenv("USER", userinfo->pw_name, 1);
		setenv("HOME", userinfo->pw_dir, 1);
	}
	else
	{
		file = params;
		*base = 0;
		if (current == config.system &&
			(http_host = getenv("HTTP_HOST")))
		{
			if (config.virtualhostdir)
				snprintf(base, XS_PATH_MAX, "%s/%s",
					calcpath(config.virtualhostdir),
					http_host);
			else
				strlcpy(base, calcpath(http_host), XS_PATH_MAX);
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
				strlcpy(base, calcpath(current->phexecdir), XS_PATH_MAX);
			}
			else
				strlcpy(base, calcpath(current->htmldir), XS_PATH_MAX);
		}
		strlcat(base, "/", XS_PATH_MAX);

		/* set euid if it wasn't set yet */
		if (!origeuid)
		{
			setegid(current->groupid);
			setgroups(1, (const gid_t *)&current->groupid);
			seteuid(current->userid);
		}
		if (!geteuid())
		{
			error("500 Effective UID is not valid");
			return;
		}
		if ((userinfo = getpwuid(geteuid())))
		{
			setenv("USER", userinfo->pw_name, 1);
			setenv("HOME", base, 1);
			userinfo = NULL;
		}
	}
	strlcpy(orgbase, base, XS_PATH_MAX);

	if (question)
	{
		/* PHP likes values starting with =
		 * libc will strip leading = from values for backward compatibility
		 * Try to accommodate both
		 */
		setenv("QUERY_STRING",
				'=' == question[1] ? question[0] = '=', question : question + 1,
				1);
		*question = 0;
	}

	if (*file)
		wasdir = (file[strlen(file) - 1] == '/');
	else
		wasdir = 0;
	if (strstr(file, "/.."))
	{
		server_error("403 Invalid path specified", "NOT_AVAILABLE");
		return;
	}
	else if (strstr(file, "/.xs") || strstr(file, "/.noxs") || strstr(file, ".redir") || strstr(file, ".Redir") || strstr(file, ".charset") || strstr(file, ".snapshot"))
	{
		server_error("404 Requested URL not found", "NOT_FOUND");
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
				setenv("SCRIPT_FILENAME", fullpath, 1);
				setenv("PWD", fullpath, 1);
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
		strlcat(base, file, XS_PATH_MAX);
		strlcat(base, "/", XS_PATH_MAX);
		file = temp + 1;
		*temp = '/';
	}
	strlcpy(currentdir, base, XS_PATH_MAX);

	if ((!*file) && (wasdir) && current->indexfiles)
	{
		filename = current->indexfiles[0];
		strlcat(real_path, filename, XS_PATH_MAX);
	}
	else
		filename = file;

	RETRY:
	/* Switch userid to system default if .xsuid exists */
	snprintf(total, XS_PATH_MAX, "%s/.xsuid", base);
	if (!stat(total, &statbuf))
	{
		if (!origeuid)
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
	/* Check for directory permissions */
	if (stat(base, &statbuf))
	{
		warn("stat(%s) failed", base);
		server_error("404 Requested URL not found", "NOT_FOUND");
		return;
	}
	if (userinfo && (statbuf.st_mode & S_IWGRP) && (statbuf.st_mode & S_IWOTH))
	{
		server_error("403 Directory permissions deny access", "NOT_AVAILABLE");
		return;
	}
	if (userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
#if 0
		error("403 Invalid owner of user directory");
		return;
#endif
	}

	mimetype[0] = scripttype[0] = '\0';
	charset[0] = encoding[0] = language[0] = '\0';
	p3pref[0] = p3pcp[0] = '\0';

	/* Check user directives */
	/* These should all send there own error messages when appropriate */
	if ((xsfile = find_file(orgbase, base, ".noxs")) && check_noxs(xsfile))
		return;
	if ((xsfile = find_file(orgbase, base, AUTHFILE)) && check_auth(xsfile))
		return;
	if (check_file_redirect(base, filename))
		return;
	if ((xsfile = find_file(orgbase, base, ".redir")) &&
			check_redirect(xsfile, real_path))
		return;
	if ((xsfile = find_file(orgbase, base, ".xsconf")) &&
			check_location(xsfile, filename))
		return;

	/* Check file permissions */
	snprintf(total, XS_PATH_MAX, "%s%s", base, filename);
	if (!lstat(total, &statbuf) && S_ISLNK(statbuf.st_mode) &&
		userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
		server_error("403 Invalid owner of symlink", "NOT_AVAILABLE");
		return;
	}
	if (stat(total, &statbuf))
	{
		int	templen = sizeof(total) - strlen(total);

		csearch = ctype;
		temp = total + strlen(total);
		while (csearch)
		{
			strlcpy(temp, csearch->ext, templen);
			if (!stat(total, &statbuf))
				break;
			csearch = csearch->next;
		}
		if (!csearch)
			goto NOTFOUND;
	}

	if (!S_ISREG(statbuf.st_mode) || delay_redir)
	{
		if (delay_redir)
		{
			/* do nothing */;
		}
		else if (!S_ISDIR(statbuf.st_mode))
		{
			server_error("403 Not a regular filename", "NOT_AVAILABLE");
			return;
		}
		else if (!strcmp(filename, INDEX_HTML) ||
			!strcmp(file, INDEX_HTML_2))
		{
			server_error("403 The index may not be a directory", "NOT_AVAILABLE");
			return;
		}
		if (wasdir)
		{
			wasdir = 0;
			strlcat(real_path, filename = INDEX_HTML, XS_PATH_MAX);
			goto RETRY;
		}
		else
		{
			char	*path_info = getenv("PATH_INFO");

			http_host = getenv("HTTP_HOST");
			if (strlen(params) > 1 &&
				'/' == params[strlen(params)-2] &&
				'.' == params[strlen(params)-1])
			{
				params[strlen(params)-2] = '\0';
				delay_redir = 0;
			}
			/* pretty url with trailing slash */
			snprintf(total, XS_PATH_MAX, "%s://%s%s%s%s%s%s%s%s",
				cursock->usessl ? "https" : "http",
				http_host ? http_host : current->hostname,
				strncmp(cursock->port, "http", 4) ? ":" : "",
				strncmp(cursock->port, "http", 4) ? cursock->port : "",
				params,
				delay_redir ? "" : "/",
				path_info ? path_info : "",
				question ? "?" : "",
				question ? question : "");

			redirect(total, 1, 0);
			return;
		}
	}
	if (userinfo &&
		(statbuf.st_mode & (S_IWGRP | S_IWOTH)) &&
		(statbuf.st_mode & S_IXUSR))
	{
		server_error("403 File permissions deny access", "NOT_AVAILABLE");
		return;
	}

	modtime = statbuf.st_mtime;
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		server_error("403 File permissions deny access", "NOT_AVAILABLE");
		return;
	}
	strlcpy(orig_filename, filename, XS_PATH_MAX);
	setenv("PATH_TRANSLATED", total, 1);

	/* Check for *.charset preferences */
	snprintf(total, XS_PATH_MAX, "%s%s.charset", base, filename);
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


	/* check for local file type */
	loadfiletypes(orgbase, base);

	/* check litype for local and itype for global settings */
	if (config.uselocalscript && !*scripttype)
		loadscripttypes(orgbase, base);
	for (i = 0; i < 3 && script >= 0; i++)
	{
	for (isearch = *isearches[i]; isearch; isearch = isearch->next)
	{
		if (!*isearch->ext ||
			*scripttype ||
			((temp = strstr(filename, isearch->ext)) &&
			 strlen(temp) == strlen(isearch->ext)))
		{
			const char	*prog = *scripttype ? scripttype : isearch->prog;

			if (!strcmp(prog, "internal:404"))
				server_error("404 Requested URL not found", "NOT_FOUND");
			else if (!strcmp(prog, "internal:text"))
			{
				script = -1;
				break;
			}
			else if (!strcmp(prog, "internal:exec"))
			{
				close(fd);
				do_script(params, base, filename, NULL, headers);
			}
			else if (!strcmp(prog, "internal:fcgi"))
			{
				close(fd);
				do_fcgi(params, base, file, headers);
			}
			else
			{
				close(fd);
				do_script(params, base, filename, prog, headers);
			}
			return;
		}
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
		server_error("405 Method not allowed", "METHOD_NOT_ALLOWED");
		setenv("HTTP_ALLOW", "GET, HEAD", 1);
		close(fd);
		return;
	}

	if (csearch)
	{
		if (strlen(csearch->name) &&
			(temp = getenv("HTTP_ACCEPT_ENCODING")) &&
			strstr(temp, csearch->name))
		{
			strlcpy(encoding, csearch->name, sizeof(encoding));
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

	/* find next possible index file */
	if (current->indexfiles)
	{
		char	*idx = NULL;

		for (i = 0; i < MAXINDEXFILES - 1; i++)
		{
			if (!(idx = current->indexfiles[i]))
				break;

			if (!strcmp(filename, idx))
			{
				if (!(idx = current->indexfiles[i + 1]))
					break;

				strlcpy(real_path + strlen(real_path) - strlen(filename), idx, XS_PATH_MAX + strlen(filename) - strlen(real_path));
				filename = idx;
				break;
			}
		}

		if (!idx)
		{
			/* no more retries */
			server_error("404 Requested URL not found", "NOT_FOUND");
			return;
		}
	}
	else
	{
		server_error("404 Requested URL not found", "NOT_FOUND");
		return;
	}

	/* add original arguments back to real_path */
	if (question)
	{
		strlcat(real_path, "?", XS_PATH_MAX);
		strlcat(real_path, question + 1, XS_PATH_MAX);
	}
	params = real_path;
	wasdir = 0;
	goto RETRY;
}

void
do_post(char *params)
{
	postonly = 1;
	do_get(params);
}

void
do_head(char *params)
{
	headonly = 1;
	do_get(params);
}

void
do_options(const char *params)
{
	secprintf("%s 200 OK\r\n", httpver);
	stdheaders(0, 0, 0);
	secputs("Content-length: 0\r\n"
		"Allow: GET, HEAD, POST, OPTIONS\r\n"
		"\r\n");
	(void)params;
}

void
do_proxy(const char *proxy, const char *params)
{
#ifdef		HAVE_CURL
	CURL	*handle = curl_easy_init();
	char	request[MYBUFSIZ], *p;

	if ((p = strstr(proxy, ":443")) || (p = strstr(proxy, ":https")))
	{
		*p = '\0'; /* or libcurl will try host:https:443 */
		snprintf(request, MYBUFSIZ, "https://%s%s", proxy, params);
		curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0);
	}
	else
		snprintf(request, MYBUFSIZ, "http://%s%s", proxy, params);
	curl_easy_setopt(handle, CURLOPT_URL, request);
	/* curl_easy_setopt(handle, CURLOPT_VERBOSE, 1); */
	if (postonly)
	{
		curl_readlen = atoi(getenv("CONTENT_LENGTH"));
		curl_easy_setopt(handle, CURLOPT_POST, 1);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, curl_readlen);
		curl_easy_setopt(handle, CURLOPT_READDATA, stdin);
		curl_easy_setopt(handle, CURLOPT_READFUNCTION, curl_readhack);
	}
	curl_easy_setopt(handle, CURLOPT_HEADER, 1);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, stdout);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, secfwrite);
	curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
	persistent = 0; headers = 10; /* force HTTP/1.0 */

	if (curl_easy_perform(handle))
		error("500 Internal forwarding error");
	else
		logrequest(params, 0);
#endif		/* HAVE_CURL */
	(void)proxy;
	(void)params;
}

#ifdef		HAVE_CURL
/* Stupid workaround for buggy libcurl */
static size_t
curl_readhack(void *buf, size_t size, size_t nmemb, FILE *stream)
{
	size_t	len;

	if (curl_readlen <= 0)
		return 0;
	if (nmemb > curl_readlen)
		nmemb = curl_readlen;
	len = secread(0, buf, size * nmemb);
	curl_readlen -= len;
	(void)stream;
	return len;
}
#endif		/* HAVE_CURL */

void
loadfiletypes(char *orgbase, char *base)
{
	char		line[LINEBUFSIZE], *name, *ext, *comment, *p;
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
		{
			warn("fopen(`%s' [read])", mimepath);
			return;
		}
	}
	prev = NULL;
	while (fgets(line, LINEBUFSIZE, mime))
	{
		if ((comment = strchr(line, '#')))
			*comment = 0;
		p = line;
		for (name = strsep(&p, " \t\n"); (ext = strsep(&p, " \t\n")); )
		{
			if (!*ext)
				continue;
			if (!(new = (ftypes *)malloc(sizeof(ftypes))))
				err(1, "Out of memory in loadfiletypes()");
			if (prev)
				prev->next = new;
			else if (base)
				lftype = new;
			else
				ftype = new;
			prev = new;
			strlcpy(new->name, name, sizeof(new->name));
			strlcpy(new->ext,  ext,  sizeof(new->ext));
			new->next = NULL;
		}
	}
	fclose(mime);
}

void
loadcompresstypes()
{
	char		line[LINEBUFSIZE], *end, *comment;
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
	{
		warn("fopen(`%s' [read])", path);
		return;
	}
	prev = NULL;
	while (fgets(line, LINEBUFSIZE, methods))
	{
		if ((comment = strchr(line, '#')))
			*comment = 0;
		end = line + strlen(line);
		while ((end > line) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (line == end)
			continue;
		if (!(new = (ctypes *)malloc(sizeof(ctypes))))
			err(1, "Out of memory in loadcompresstypes()");
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

void
loadscripttypes(char *orgbase, char *base)
{
	char		line[LINEBUFSIZE], *end, *comment, *path;
	FILE		*methods;
	ctypes		*prev, *new;

	if (orgbase && base)
	{
		while (litype)
			{ new = litype->next; free(litype); litype = new; }
		if (ditype)
			{ free(ditype); ditype = NULL; }
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
	while (fgets(line, LINEBUFSIZE, methods))
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
			err(1, "Out of memory in loadscripttypes()");
		if (sscanf(line, "%s %s", new->prog, new->ext) != 2)
			errx(1, "Unable to parse `%s' in `%s'", line, path);
		new->next = NULL;
		if (!strcmp(new->ext, "*"))
		{
			/* there can be only one default */
			if (ditype)
				free(ditype);
			new->ext[0] = '\0';
			ditype = new;
		}
		else
		{
			if (prev)
				prev->next = new;
			else if (base)
				litype = new;
			else
				itype = new;
			prev = new;
		}
	}
	free(path);
	fclose(methods);
}

#ifdef		HANDLE_PERL
void
loadperl()
{
	const char *embedding[] = { "", HTTPD_ROOT "/persistent.pl" };
	int exitstatus = 0;

	if (!(my_perl = perl_alloc()))
	   err(1, "No memory!");
	perl_construct(my_perl);

	exitstatus = perl_parse(my_perl, NULL, 2, embedding, NULL);
	if (!exitstatus)
	   exitstatus = perl_run(my_perl);
	else
		err(1, "No perl!");
}
#endif		/* HANDLE_PERL */

static int
getfiletype(int print)
{
	const	ftypes	*search, *flist[2];
	const	int	flen = sizeof(flist) / sizeof(ftypes *);
	const	char	*ext;
	char		extension[20];
	int		i, count;

	flist[0] = lftype; flist[1] = ftype;

	if (*mimetype || !(ext = strrchr(orig_filename, '.')) || !(*(++ext)))
	{
		if (print)
		{
			if (*charset)
				secprintf("Content-type: %s; charset=%s\r\n",
						*mimetype ? mimetype : "text/plain",
						charset);
			else
				secprintf("Content-type: %s\r\n",
						*mimetype ? mimetype : "text/plain");
		}
		return !strcasecmp(mimetype, "text/html");
	}
	for (count = 0; ext[count] && (count < 16); count++)
		extension[count] =
			isupper(ext[count]) ? tolower(ext[count]) : ext[count];
	extension[count] = 0;
	for (i = 0; i < flen; i++)
	{
		for (search = flist[i]; search; search = search->next)
		{
			if (strcmp(extension, search->ext))
				continue;
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
			return !strcasecmp(search->name, "text/html");
		}
	}
	if (print)
		secprintf("Content-type: application/octet-stream\r\n");
	return(0);
}

int
check_file_redirect(const char *base, const char *filename)
{
	int	fd, size, permanent = 0;
	char	*p, *subst, total[XS_PATH_MAX];

	/* Check for *.redir instructions */
	snprintf(total, XS_PATH_MAX, "%s%s.redir", base, filename);
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		snprintf(total, XS_PATH_MAX, "%s%s.Redir", base, filename);
		if ((fd = open(total, O_RDONLY, 0)) >= 0)
			permanent = 1;
	}
	if (fd >= 0)
	{
		if ((size = read(fd, total, XS_PATH_MAX)) <= 0)
		{
			error("500 Redirection filename error");
			close(fd);
			return 1;
		}
		total[size] = 0;
		p = total;
		subst = strsep(&p, " \t\r\n");
		redirect(subst, permanent, 1);
		close(fd);
		return 1;
	}
	return 0;
}

int
check_redirect(FILE *fp, const char *filename)
{
	int	size;
	char	*p, *command, *subst,
		*host, *orig, *repl,
		line[XS_PATH_MAX], total[XS_PATH_MAX], request[XS_PATH_MAX];

	strlcpy(request, filename, XS_PATH_MAX);

	while (fgets(line, XS_PATH_MAX, fp))
	{
		p = line;
		while ((command = strsep(&p, " \t\r\n")) && !*command)
			/* continue */;

		/* skip comments and blank lines */
		if (!command || !*command || '#' == *command)
			continue;

		/* use pcre matching */
		if (!strcasecmp(command, "pass"))
		{
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			if (pcre_match(request, orig) > 0)
			{
				fclose(fp);
				return 0;
			}
		}
		else if (!strcasecmp(command, "redir"))
		{
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			while ((repl = strsep(&p, " \t\r\n")) && !*repl)
				/* continue */;
			if ((subst = pcre_subst(request, orig, repl)) &&
					*subst)
			{
				redirect(subst, 'R' == command[0], 0);
				free(subst);
				fclose(fp);
				return 1;
			}
		}
		else if (!strcasecmp(command, "rewrite"))
		{
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			while ((repl = strsep(&p, " \t\r\n")) && !*repl)
				/* continue */;
			if ((subst = pcre_subst(request, orig, repl)) &&
					*subst)
			{
				do_get(subst);
				free(subst);
				fclose(fp);
				return 1;
			}
		}
		else if (!strcasecmp(command, "forward"))
		{
			while ((host = strsep(&p, " \t\r\n")) && !*host)
				/* continue */;
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			while ((repl = strsep(&p, " \t\r\n")) && !*repl)
				/* continue */;
			if ((subst = pcre_subst(request, orig, repl)) &&
					*subst)
			{
				do_proxy(host, subst);
				free(subst);
				fclose(fp);
				return 1;
			}
		}
		else /* no command: redir to url */
		{
			size = strlen(command);
			if (size && '/' == command[size - 1])
				command[size - 1] = '\0';
			snprintf(total, XS_PATH_MAX, "%s/%s",
				command, request);
			redirect(total, 0, 1);
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}
