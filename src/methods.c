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
#ifdef		HAVE_SYS_SELECT_H
#include	<sys/select.h>
#endif		/* HAVE_SYS_SELECT_H */
#ifdef		HAVE_SYS_PARAM_H
#include	<sys/param.h>
#endif		/* HAVE_SYS_PARAM_H */
#ifdef		HAVE_SYS_SENDFILE_H
#include	<sys/sendfile.h>
#endif		/* HAVE_SYS_SENDFILE_H */

#include	<fcntl.h>
#include	<stdio.h>
#include	<errno.h>
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
#include	<netinet/in.h>
#include	<netinet/tcp.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"decode.h"
#include	"methods.h"
#include	"convert.h"
#include	"ssi.h"
#include	"ssl.h"
#include	"extra.h"
#include	"cgi.h"
#include	"path.h"
#include	"pcre.h"
#include	"authenticate.h"
#include	"xsfiles.h"
#include	"malloc.h"

#ifdef		HAVE_LIBMD
MD5_CTX		*md5context;
#endif		/* HAVE_LIBMD */

static bool	getfiletype		(bool);
static bool	sendheaders		(int, off_t);
static void	senduncompressed	(int);
static void	sendcompressed		(int, const char *);
static char *	find_file		(const char *, const char *, const char *)	MALLOC_FUNC;
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

static	cf_values		cfvalues;
static	bool	dynamic = false;
#ifdef		HAVE_CURL
static	size_t	curl_readlen;
#endif		/* HAVE_CURL */
static	char	orig_pathname[XS_PATH_MAX];

static char *
make_etag(struct stat *sb)
{
#define	ETAG_LEN	(sizeof(time_t) + sizeof(ino_t) + sizeof(off_t))
#define	ETAG_SLEN	(2 * ETAG_LEN + 3)
	static char	etag[ETAG_SLEN];
	char		binbuf[ETAG_LEN], *p;
	time_t		modtime;

	if (!sb || !config.useetag)
	{
		etag[0] = '\0';
		return NULL;
	}

	/* etag = inode . modtime . size
	 * Warning: this value is system dependent,
	 * check struct sizes, definitions, endianness
	 */
	p = binbuf;
	modtime = sb->st_mtime;
	memcpy(p, &sb->st_ino, sizeof(ino_t));
	p += sizeof(ino_t);
	memcpy(p, &modtime, sizeof(time_t));
	p += sizeof(modtime);
	memcpy(p, &sb->st_size, sizeof(off_t));
	/* prepend id */
	memcpy(etag, SERVER_IDENT, 2);
	hex_encode(binbuf, ETAG_LEN, etag + 2);

	/* strip trailing zeros (on little endian systems) */
	p = etag + 2 + 2 * ETAG_LEN;
	while ('0' == *--p && '0' == *--p)
		*p = '\0';

	return etag;
}

static bool
sendheaders(int fd, off_t size)
{
	char		*env, *etag;
	time_t		modtime;
	struct tm	reqtime;

	dynamic = false;

	/* This is extra overhead, overhead, overhead! */
	if (config.usessi && getfiletype(false))
	{
		char input[RWBUFSIZE];

		/* fgets is better: read() may split HTML tags! */
		while (read(fd, input, RWBUFSIZE))
			if (strstr(input, "<!--#"))
			{
				dynamic = true;
				break;
			}
		lseek(fd, (off_t)0, SEEK_SET);
	}

	modtime = 0;
	etag = NULL;
	if (!dynamic)
	{
		struct stat	statbuf;

		if (!fstat(fd, &statbuf))
		{
			modtime = statbuf.st_mtime;
			etag = make_etag(&statbuf);
		}
	}

	if (etag &&
		((env = getenv("HTTP_IF_MATCH")) ||
		 (env = getenv("HTTP_IF_NONE_MATCH"))))
	{
		size_t	i, m, sz;
		char	**list = NULL;
		int	abort_wo_match = !!getenv("HTTP_IF_MATCH");

		sz = qstring_to_arrayp(env, &list);
		for (i = 0; i < sz; i++)
		{
			if (!list[i] || list[i][0])
				continue;
			if (!strcmp(list[i], etag))
				break;
			else if (!strcmp(list[i], "*"))
				break;
		}
		m = i;
		if (list)
		{
			for (i = 0; i < sz; i++)
				free(list[i]);
			free(list);
		}
		if ((abort_wo_match && (m >= sz)) ||
			(!abort_wo_match && (m < sz)))
		{
			/* exit with error
			 * unless If-None-Match && method == GET
			 */
			if (abort_wo_match ||
				strcmp(getenv("REQUEST_METHOD"), "GET"))
			{
				server_error(412, "Precondition failed",
					"PRECONDITION_FAILED");
				return false;
			}
		}
	}
	if ((env = getenv("HTTP_IF_MODIFIED_SINCE")))
	{
		strptime(env, "%a, %d %b %Y %H:%M:%S %Z", &reqtime);
		if (!dynamic && (mktime(&reqtime) >= modtime))
		{
			headonly = true;
			rstatus = 304;
			secprintf("%s 304 Not modified\r\n", httpver);
		}
	}
	else if ((env = getenv("HTTP_IF_UNMODIFIED_SINCE")))
	{
		strptime(env, "%a, %d %b %Y %H:%M:%S %Z", &reqtime);
		if (dynamic || (mktime(&reqtime) >= modtime))
		{
			server_error(412, "Precondition failed",
				"PRECONDITION_FAILED");
			return false;
		}
	}
	/* set mimetype and charset */
	getfiletype(true);
	if (getenv("HTTP_ACCEPT"))
	{
		size_t		i, acsz, len;
		char		*ac = getenv("HTTP_ACCEPT");
		char 		**acceptlist = NULL;

		acsz = qstring_to_arrayp(ac, &acceptlist);
		for (i = 0; i < acsz; i++)
		{
			if (!strcmp(acceptlist[i], "*/*"))
				break;
			else if (!strcasecmp(acceptlist[i], cfvalues.mimetype))
				break;

			/* check for partial match */
			len = strlen(acceptlist[i]);
			if (!strcmp(&acceptlist[i][len - 2], "/*") &&
				!strncasecmp(acceptlist[i], cfvalues.mimetype,
					len - 1))
				break;
		}
		if (acceptlist)
		{
			free(acceptlist);
			if (i >= acsz)
			{
				server_error(406, "Not acceptable",
					"NOT_ACCEPTABLE");
				return false;
			}
		}
	}
	if (getenv("HTTP_ACCEPT_CHARSET") && cfvalues.charset)
	{
		size_t		i, acsz;
		char		*ac = getenv("HTTP_ACCEPT_CHARSET");
		char 		**acceptlist = NULL;

		acsz = qstring_to_arrayp(ac, &acceptlist);
		for (i = 0; i < acsz; i++)
			if (!strcmp(acceptlist[i], "*"))
				break;
			else if (!strcasecmp(acceptlist[i], cfvalues.charset))
				break;
		if (acceptlist)
		{
			free(acceptlist);
			if (i >= acsz)
			{
				server_error(406, "Charset not acceptable",
					"NOT_ACCEPTABLE");
				return false;
			}
		}
	}

	/* All preconditions satisfied */
	secprintf("%s 200 OK\r\n", httpver);
	stdheaders(false, false, false);
	if (cfvalues.charset)
		secprintf("Content-type: %s; charset=%s\r\n",
			cfvalues.mimetype, cfvalues.charset);
	else
		secprintf("Content-type: %s\r\n", cfvalues.mimetype);

	if (dynamic)
	{
		if (headers >= 11)
		{
			secprintf("Cache-control: no-cache\r\n");
			secputs("Transfer-encoding: chunked\r\n");
			if (config.usecontentmd5 && trailers)
				secprintf("Trailer: Content-MD5\r\n");
		}
		else
			secprintf("Pragma: no-cache\r\n");
	}
	else
	{
#ifdef		HAVE_LIBMD
		char	digest[MD5_DIGEST_LENGTH];
		char	hex_digest[MD5_DIGEST_STRING_LENGTH];
		char	base64_data[MD5_DIGEST_B64_LENGTH];
#endif		/* HAVE_MD5 */
		char	modified[32];

		secprintf("Content-length: %" PRId64 "\r\n", (int64_t)size);
#ifdef		HAVE_LIBMD
		if (config.usecontentmd5)
		{
			MD5File(orig_pathname, hex_digest);
			hex_decode(hex_digest, MD5_DIGEST_STRING_LENGTH-1, digest);
			base64_encode(digest, MD5_DIGEST_LENGTH, base64_data);
			secprintf("Content-MD5: %s\r\n", base64_data);
		}
#endif		/* HAVE_MD5 */

		strftime(modified, sizeof(modified),
			"%a, %d %b %Y %H:%M:%S GMT", gmtime(&modtime));
		secprintf("Last-modified: %s\r\n", modified);
	}

	if (etag)
		secprintf("ETag: %s\r\n", etag);

	if (cfvalues.encoding)
		secprintf("Content-encoding: %s\r\n", cfvalues.encoding);

	if (cfvalues.language)
		secprintf("Content-language: %s\r\n", cfvalues.language);

	if (cfvalues.p3pref && cfvalues.p3pcp)
		secprintf("P3P: policyref=\"%s\", CP=\"%s\"\r\n",
			cfvalues.p3pref, cfvalues.p3pcp);
	else if (cfvalues.p3pref)
		secprintf("P3P: policy-ref=\"%s\"\r\n", cfvalues.p3pref);
	else if (cfvalues.p3pcp)
		secprintf("P3P: CP=\"%s\"\r\n", cfvalues.p3pcp);

	secprintf("\r\n");
	return true;
}

static void
senduncompressed(int fd)
{
	off_t		size;

	alarm(180);

	size = lseek(fd, 0, SEEK_END);
	if (-1 == size)
	{
		xserror(500, "Cannot lseek() to end of file");
		close(fd);
		return;
	}
	if (lseek(fd, 0, SEEK_SET))
	{
		xserror(500, "Cannot lseek() to beginning of file");
		close(fd);
		return;
	}
	if (headers >= 10)
	{
		if (!sendheaders(fd, size))
		{
			close(fd);
			return;
		}
	}

	if (headonly)
		goto DONE;

	UNPARSED:
	if (!dynamic)
	{
		ssize_t		written;
		alarm((size / MINBYTESPERSEC) + 20);

		fflush(stdout);
#ifdef		TCP_NOPUSH
		if (setsockopt(1, IPPROTO_TCP, TCP_NOPUSH, (int[]){1}, sizeof(int)) < 0)
			warnx("setsockopt(IPPROTO_TCP)");
#endif		/* TCP_NOPUSH */

#ifdef		HAVE_BSD_SENDFILE
		if (!cursock->usessl && !chunked)
		{
			if (sendfile(fd, 1, 0, size, NULL, NULL, 0) < 0)
				xserror(599, "Aborted sendfile for `%s'",
					remotehost[0] ? remotehost : "(none)");
		}
		else
#endif		/* HAVE_BSD_SENDFILE */
#ifdef		HAVE_LINUX_SENDFILE	/* cannot have both */
		if (!cursock->usessl && !chunked)
		{
			if (sendfile(1, fd, NULL, size) < 0)
				xserror(599, "Aborted sendfile for `%s'",
					remotehost[0] ? remotehost : "(none)");
		}
		else
#endif		/* HAVE_LINUX_SENDFILE */
#ifdef		HAVE_MMAP
		/* don't use mmap() for files >12Mb to avoid hogging memory */
		if (size < 12 * 1048576)
		{
			char		*buffer;
			size_t		msize = (size_t)size;

			if ((buffer = (char *)mmap((caddr_t)0, msize, PROT_READ,
				MAP_SHARED, fd, (off_t)0)) == (char *)-1)
				err(1, "[%s] httpd: mmap() failed", currenttime);
			if ((size_t)(written = secwrite(buffer, msize)) != msize)
			{
				if (written != -1)
					xserror(599, "Aborted for `%s' (%zu of %zu bytes sent)",
						remotehost[0] ? remotehost : "(none)",
						written, msize);
				else
					xserror(599, "Aborted for `%s'",
						remotehost[0] ? remotehost : "(none)");
			}
			(void) munmap(buffer, msize);
			size = written;
		}
		else
#endif		/* HAVE_MMAP */
		/* send static content without mmap() */
		{
			char		*buffer;
			ssize_t		readtotal;
			off_t		writetotal;

			MALLOC(buffer, char, 100 * RWBUFSIZE);
			writetotal = 0;
			while ((readtotal = read(fd, buffer, 100 * RWBUFSIZE)) > 0)
			{
				if ((written = secwrite(buffer, (size_t)readtotal))
						!= readtotal)
				{
					xserror(599, "Aborted for `%s' (No mmap) (%" PRId64
							" of %" PRId64 " bytes sent)",
						remotehost[0] ? remotehost : "(none)",
						(int64_t)writetotal + written, size);
					size = writetotal;
					goto DONE;
				}
				writetotal += written;
			}
			size = writetotal;
			free(buffer);
		}
	}
	else /* dynamic content only */
	{
		off_t		usize = 0;
		int		errval;

		if (headers >= 11)
		{
			chunked = true;
#ifdef		HAVE_LIBMD
			if (config.usecontentmd5 && trailers)
			{
				MALLOC(md5context, MD5_CTX, 1);
				MD5Init(md5context);
			}
#endif		/* HAVE_LIBMD */
		}
		alarm((size / MINBYTESPERSEC) + 60);
		errval = sendwithdirectives(fd, &usize);
		if (usize)
			size = usize;
		close(fd);
		switch(errval)
		{
		case ERR_QUIT:
			xserror(599, "Aborted for `%s' (ERR_QUIT)",
				remotehost[0] ? remotehost : "(none)");
			break;
		case ERR_CONT:
			goto UNPARSED;
		default:
			break;
		}
	}

	DONE:
	alarm(0);
#ifdef		TCP_NOPUSH
	/* silently reset tcp flags */
	setsockopt(1, IPPROTO_TCP, TCP_NOPUSH, (int[]){0}, sizeof(int));
#endif		/* TCP_NOPUSH */
	logrequest(real_path, size);
	close(fd);
}

static void
sendcompressed(int fd, const char *method)
{
	pid_t		pid;
	int		processed;

	/* local block */
	{
		char	prefix[] = TEMPORARYPREFIX;

		if (!(processed = mkstemp(prefix)))
		{
			xserror(500, "Unable to open temporary file");
			err(1, "[%s] httpd: Cannot create temporary file",
				currenttime);
		}
		remove(prefix);
	}

	switch(pid = fork())
	{
	case -1:
		warn("fork()");
		xserror(500, "Cannot fork() in sendcompressed()");
		close(fd); close(processed); return;
	case 0:
#ifdef		HAVE_SETSID
		if (setsid() == -1)
		{
			xserror(500, "Process group error");
			exit(1);
		}
#else		/* Not HAVE_SETSID */
		if (setpgrp(getpid(), 0) == -1)
		{
			xserror(500, "Process group error)");
			exit(1);
		}
#endif		/* HAVE_SETSID */
		dup2(fd, 0); dup2(processed, 1);

		closefrom(3);
		(void) execl(method, method, NULL);
		xserror(500, "Cannot start conversion program");
		exit(1);
	default:
		close(fd);
		if (!kill(pid, 0) && mysleep(180))
		{
			close(processed);
			killpg(pid, SIGTERM);
			mysleep(3);
			killpg(pid, SIGKILL);
			xserror(500, "Conversion program timed out");
			return;
		}
		if (!kill(pid, 0))
		{
			close(processed);
			killpg(pid, SIGKILL);
			xserror(500, "Interrupted during conversion");
			return;
		}
	}
	senduncompressed(processed);
}

static	char	*
find_file(const char *orgbase, const char *base, const char *file)
{
	static char	path[XS_PATH_MAX];
	char		*p;
	size_t		len = strlen(orgbase);
	struct stat	sb;

	/* Check after redirection */
	/* Ugly way to do this recursively */
	snprintf(path, XS_PATH_MAX, "%s/", base);
	for (p = path;
		(p == path || !strncmp(orgbase, path, len)) &&
		(p = strrchr(path, '/'));
		*p = '\0')
	{
		snprintf(p, (size_t)(XS_PATH_MAX - (p - path)), "/%s", file);
		if (!stat(path, &sb))
			return path;
	}

	return NULL;
}

void
do_get(char *params)
{
	char			*temp, *file, *cgi, *question, *method,
				base[XS_PATH_MAX], orgbase[XS_PATH_MAX],
				total[XS_PATH_MAX], temppath[XS_PATH_MAX];
	const	char		*filename, *http_host;
	int			fd, script = 0;
	bool			wasdir, switcheduid = false,
				delay_redir = false;
	size_t			size;
	struct	stat		statbuf;
	const	struct	passwd	*userinfo;
	FILE			*charfile;
	char			*xsfile;
	const	ctypes		*csearch = NULL, *isearch = NULL;

	alarm(240);

	/* Sanitize the requested path */
	question = strchr(params, '?');
	while ((temp = strstr(params, "//")))
		if (!question || (temp < question))
		{
			delay_redir = true;
			memmove(temp, temp + 1, strlen(temp));
			if (question)
				question--;
		}
		else
			break;
	while ((temp = strstr(params, "/./")))
		if (!question || (temp < question))
		{
			delay_redir = true;
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
			*temp = '\0';
		userinfo = getpwnam(params + 2);
		if (!userinfo)
		{
			server_error(404, "User is unknown", "USER_UNKNOWN");
			return;
		}
		strlcpy(base, convertpath(params), XS_PATH_MAX);
		if (!*base)
		{
			server_error(404, "User is unknown", "USER_UNKNOWN");
			return;
		}
		if (!origeuid)
		{
			setegid(userinfo->pw_gid);
			setgroups(1, (const gid_t *)&userinfo->pw_gid);
			seteuid(userinfo->pw_uid);
		}
		if (!geteuid())
		{
			xserror(500, "Effective UID is not valid");
			return;
		}
		if (temp)
		{
			*temp = '/';
			file = temp;
		}
		else
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
					xserror(500, "Effective UID is not valid");
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
			else if (!strncmp(params + 1, ICON_DIR, strlen(ICON_DIR)))
			{
				file += strlen(ICON_DIR) + 2;
				strlcpy(base, calcpath(current->icondir), XS_PATH_MAX);
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
			xserror(500, "Effective UID is not valid");
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
		char	*qs;
		qs = '=' == question[1]
			? question[0] = '=', question
			: question + 1;
		setenv("QUERY_STRING", qs, 1);
		qs = shellencode(qs);
		setenv("QUERY_STRING_UNESCAPED", qs, 1);
		free(qs);
		*question = 0;
	}

	if (*file)
		wasdir = (file[strlen(file) - 1] == '/');
	else
		wasdir = false;
	if (strstr(file, "/.."))
	{
		server_error(403, "Invalid path specified", "NOT_AVAILABLE");
		return;
	}
	else if (strstr(file, "/.xs") || strstr(file, "/.noxs") || strstr(file, ".redir") || strstr(file, ".Redir") || strstr(file, ".charset") || strstr(file, "/.snapshot"))
	{
		server_error(404, "Requested URL not found", "NOT_FOUND");
		return;
	}
	else if (strstr(file, current->execdir) && (temp = strrchr(file, '/')) && !strcmp(temp, "/error"))
	{
		server_error(404, "Requested URL not found", "NOT_FOUND");
		return;
	}

	if (*file == '/' && file[1] != '\0')
		file++;
	cgi = file;

	/* look for file on disk */
	snprintf(temppath, XS_PATH_MAX, "%s%s", base, file);
	if (wasdir &&
		!stat(temppath, &statbuf) &&
		(statbuf.st_mode & S_IFMT) == S_IFDIR)
	{
		setenv("SCRIPT_NAME", params, 1);
		setenv("SCRIPT_FILENAME", temppath, 1);
		setenv("PWD", temppath, 1);
	}
	else if (!wasdir &&
		!stat(temppath, &statbuf) &&
		(statbuf.st_mode & S_IFMT) == S_IFREG)
	{
		/* No PATH_INFO for regular files */
		if (!getenv("ORIG_PATH_TRANSLATED"))
			setenv("ORIG_PATH_TRANSLATED", temppath, 1);
		setenv("SCRIPT_NAME", params, 1);
		setenv("SCRIPT_FILENAME", temppath, 1);
		if ((temp = strrchr(temppath, '/')))
		{
			*temp = '\0';
			setenv("PWD", temppath, 1);
			*temp = '/';
		}
	}
	else
	{
		temp = file;
		while ((temp = strchr(temp, '/')))
		{
			char fullpath[XS_PATH_MAX], *slash;

			*temp = 0;
			snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);
			if (stat(fullpath, &statbuf))
				break; /* error later */
			if ((statbuf.st_mode & S_IFMT) == S_IFREG)
			{
				setenv("SCRIPT_NAME", params, 1);
				setenv("SCRIPT_FILENAME", fullpath, 1);
				*temp = '/';
				setenv("PATH_INFO", temp, 1);
				setenv("PATH_TRANSLATED", convertpath(temp), 1);
				if ((slash = strrchr(fullpath, '/')))
					*slash = '\0';
				setenv("PWD", fullpath, 1);
				*temp = '\0';

				/* opt. set uid to path_info user */
				if (current->uidscripts && '~' == temp[1] &&
					(slash = strchr(&temp[2], '/')) && !origeuid)
				{
					*slash = '\0';
					for (int i = 0; current->uidscripts[i]; i++)
						if (!strcmp(params, current->uidscripts[i]))
						{
							userinfo = getpwnam(&temp[2]);
							if (!userinfo || !userinfo->pw_uid)
								break;
							seteuid(origeuid);
							setegid(userinfo->pw_gid);
							setgroups(1, (const gid_t *)&userinfo->pw_gid);
							seteuid(userinfo->pw_uid);
							break;
						}
					*slash = '/';
				}
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
		char	*newpath;

		setenv("PWD", currentdir, 1);
		filename = current->indexfiles[0];
		strlcat(real_path, filename, XS_PATH_MAX);
		strlcat(currentdir, filename, XS_PATH_MAX);
		asprintf(&newpath, "%s%s", base, real_path);
		setenv("SCRIPT_FILENAME", newpath, 1);
		free(newpath);
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
			switcheduid = true;
		}
		if (!geteuid())
		{
			xserror(500, "Effective UID is not valid");
			return;
		}
	}
	/* Check for directory permissions */
	if (stat(base, &statbuf))
	{
		warn("stat(`%s')", base);
		server_error(404, "Requested URL not found", "NOT_FOUND");
		return;
	}
	if (userinfo && (statbuf.st_mode & S_IWGRP) && (statbuf.st_mode & S_IWOTH))
	{
		server_error(403, "Directory permissions deny access", "NOT_AVAILABLE");
		return;
	}
	if (userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
#if 0
		xserror(403, "Invalid owner of user directory");
		return;
#endif
	}

	memset(&cfvalues, 0, sizeof(cfvalues));

	/* Check user directives */
	/* These should all send there own error messages when appropriate */
	if ((xsfile = find_file(orgbase, base, NOXS_FILE)) && check_noxs(xsfile))
		return;
	if ((xsfile = find_file(orgbase, base, AUTH_FILE)) && !check_auth(xsfile, NULL))
		return;
	if (check_file_redirect(base, filename))
		return;
	if ((xsfile = find_file(orgbase, base, REDIR_FILE)) &&
			check_redirect(xsfile, real_path))
		return;
	if ((xsfile = find_file(orgbase, base, CONFIG_FILE)) &&
			check_xsconf(xsfile, filename, &cfvalues))
		return;

	/* PUT and DELETE are handled by CGI scripts */
	method = getenv("REQUEST_METHOD");
	if (!strcasecmp(method, "PUT") || !strcasecmp(method, "DELETE"))
	{
		const char	*path;

		if ((path = getenv("REQUEST_URI")))
		{
			setenv("PATH_INFO", path, 1);
			setenv("PATH_TRANSLATED", convertpath(path), 1);
		}
		if (cfvalues.putscript)
		{
			if (!strcasecmp(method, "PUT"))
				do_script(params, base, file, cfvalues.putscript);
			else
				do_script(params, base, file, cfvalues.delscript);
		}
		else
		{
			setenv("HTTP_ALLOW", "GET, HEAD, POST", 1);
			server_error(405, "Method not allowed", "METHOD_NOT_ALLOWED");
		}
		free_xsconf(&cfvalues);
		return;
	}

	/* Check file permissions */
	snprintf(total, XS_PATH_MAX, "%s%s", base, filename);
	if (!lstat(total, &statbuf) && S_ISLNK(statbuf.st_mode) &&
		userinfo && statbuf.st_uid && (statbuf.st_uid != geteuid()))
	{
		server_error(403, "Invalid owner of symlink", "NOT_AVAILABLE");
		free_xsconf(&cfvalues);
		return;
	}
	if (stat(total, &statbuf))
	{
		unsigned int	templen = sizeof(total) - strlen(total);

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
			server_error(403, "Not a regular filename", "NOT_AVAILABLE");
			free_xsconf(&cfvalues);
			return;
		}
		else if (!strcmp(filename, INDEX_HTML))
		{
			server_error(403, "The index may not be a directory", "NOT_AVAILABLE");
			free_xsconf(&cfvalues);
			return;
		}
		if (wasdir)
		{
			wasdir = false;
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
				delay_redir = false;
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
			free_xsconf(&cfvalues);
			return;
		}
	}
	if (userinfo &&
		(statbuf.st_mode & (S_IWGRP | S_IWOTH)) &&
		(statbuf.st_mode & S_IXUSR))
	{
		server_error(403, "File permissions deny access", "NOT_AVAILABLE");
		free_xsconf(&cfvalues);
		return;
	}

	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		server_error(403, "File permissions deny access", "NOT_AVAILABLE");
		free_xsconf(&cfvalues);
		return;
	}
	strlcpy(orig_filename, filename, XS_PATH_MAX);
	strlcpy(orig_pathname, total, XS_PATH_MAX);

	/* Check for *.charset preferences */
	if (!cfvalues.charset)
	{
		char	lcharset[XS_PATH_MAX];

		snprintf(total, XS_PATH_MAX, "%s%s.charset", base, filename);
		if ((charfile = fopen(total, "r")) ||
			((xsfile = find_file(orgbase, base, ".charset")) &&
			 (charfile = fopen(xsfile, "r"))))
		{
			if (fread(lcharset, 1, XS_PATH_MAX, charfile))
			{
				lcharset[XS_PATH_MAX-1] = '\0';
				if ((temp = strchr(lcharset, '\n')))
					temp[0] = '\0';
				cfvalues.charset = strdup(lcharset);
			}
			fclose(charfile);
		}
	}

	/* check for local file type */
	loadfiletypes(orgbase, base);

	/* check litype for local and itype for global settings */
	if (config.uselocalscript && !cfvalues.scripttype)
		loadscripttypes(orgbase, base);
	for (int i = 0; i < 3 && script >= 0; i++)
	{
	for (isearch = *isearches[i]; isearch; isearch = isearch->next)
	{
		if (!*isearch->ext ||
			cfvalues.scripttype ||
			((temp = strstr(filename, isearch->ext)) &&
			 strlen(temp) == strlen(isearch->ext)))
		{
			const char	*prog = cfvalues.scripttype ? cfvalues.scripttype : isearch->prog;

			if (!strcmp(prog, "internal:404"))
				server_error(404, "Requested URL not found", "NOT_FOUND");
			else if (!strcmp(prog, "internal:text"))
			{
				script = -1;
				break;
			}
			else if (!strcmp(prog, "internal:exec"))
			{
				close(fd);
				do_script(params, base, filename, NULL);
			}
#if		0	/* not production ready */
			else if (!strcmp(prog, "internal:fcgi"))
			{
				close(fd);
				do_fcgi(params, base, file, headers);
			}
#endif		/* 0 */
			else
			{
				close(fd);
				do_script(params, base, filename, prog);
			}
			free_xsconf(&cfvalues);
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
			do_script(params, base, file, NULL);
			free_xsconf(&cfvalues);
			return;
		}
	}

	if (postonly)
	{
		setenv("HTTP_ALLOW", "GET, HEAD", 1);
		server_error(405, "Method not allowed", "METHOD_NOT_ALLOWED");
		close(fd);
		free_xsconf(&cfvalues);
		return;
	}

	if (csearch)
	{
		if (strlen(csearch->name) &&
			(temp = getenv("HTTP_ACCEPT_ENCODING")) &&
			strstr(temp, csearch->name))
		{
			cfvalues.encoding = strdup(csearch->name);
			senduncompressed(fd);
		}
		else
			sendcompressed(fd, csearch->prog);
	}
	else
		senduncompressed(fd);
	free_xsconf(&cfvalues);
	return;

	NOTFOUND:
	if ((temp = strchr(real_path, '?')))
		*temp = '\0';

	/* find next possible index file */
	if (cfvalues.indexfile && (temp = strrchr(real_path, '/')))
	{
		*++temp = '\0';
		strlcat(real_path, cfvalues.indexfile, XS_PATH_MAX);
		filename = temp;
	}
	else if (current->indexfiles)
	{
		char	*idx = NULL;

		for (int i = 0; i < MAXINDEXFILES - 1; i++)
		{
			if (!(idx = current->indexfiles[i]))
				break;

			if (!strcmp(filename, idx))
			{
				if (!(idx = current->indexfiles[i + 1]))
					break;

				if (strlen(filename) && strlen(real_path) > strlen(filename))
				{
					real_path[strlen(real_path) - strlen(filename)] = '\0';
					strlcat(real_path, idx, XS_PATH_MAX);
				}
				else
					snprintf(real_path, XS_PATH_MAX, "/%s", idx);
				filename = idx;
				break;
			}
		}

		if (!idx)
		{
			/* no more retries */
			server_error(404, "Requested URL not found", "NOT_FOUND");
			free_xsconf(&cfvalues);
			return;
		}
	}
	else
	{
		server_error(404, "Requested URL not found", "NOT_FOUND");
		free_xsconf(&cfvalues);
		return;
	}

	/* add original arguments back to real_path */
	setenv("SCRIPT_FILENAME", convertpath(real_path), 1);
	if (getenv("QUERY_STRING"))
	{
		strlcat(real_path, "?", XS_PATH_MAX);
		strlcat(real_path, getenv("QUERY_STRING"), XS_PATH_MAX);
	}
	params = real_path;
	wasdir = false;
	goto RETRY;
}

void
do_post(char *params)
{
	const	char	* const cl = getenv("CONTENT_LENGTH");

	postonly = true;	/* const: this is a post */
	postread = false;	/* var: modified when data buffer is read */
	do_get(params);

	/* flush data buffer if posting was never read */
	if (!postread && cl)
	{
		size_t	rlen;
		char	*rbuf;
			
		errno = 0;
		rlen = strtoul(cl, NULL, 10);
		if (ERANGE == errno)
		{
			server_error(413, "Request Entity Too Large",
				"ENTITY_TOO_LARGE");
			return;
		}
		MALLOC(rbuf, char, rlen + 1);
		secread(0, rbuf, rlen);
		free(rbuf);
	}
}

void
do_put(char *params)
{
	if (!config.useput)
	{
		server_error(405, "Method not allowed", "METHOD_NOT_ALLOWED");
		setenv("HTTP_ALLOW", "GET, HEAD, POST", 1);
		return;
	}
	do_post(params);
}

void
do_delete(char *params)
{
	if (!config.useput)
	{
		server_error(405, "Method not allowed", "METHOD_NOT_ALLOWED");
		setenv("HTTP_ALLOW", "GET, HEAD, POST", 1);
		return;
	}
	do_get(params);
}

void
do_head(char *params)
{
	headonly = true;
	do_get(params);
}

void
do_options(const char *params)
{
	secprintf("%s 200 OK\r\n", httpver);
	stdheaders(false, false, false);
	secputs("Content-length: 0\r\n"
		"Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE\r\n"
		"\r\n");
	(void)params;
}

void
do_trace(const char *params)
{
	struct	maplist		http_headers;
	char		*output;
	size_t		outlen, mlen;
	ssize_t		num;

	num = readheaders(0, &http_headers);
	if (num < 0)
	{
		xserror(400, "Unable to read request line");
		return;
	}
	mlen = LINEBUFSIZE;
	MALLOC(output, char, mlen);

	if (num && !strcasecmp(http_headers.elements[0].index, "Status"))
		outlen = snprintf(output, mlen, "%s\r\n",
			http_headers.elements[1].value);
	else
		outlen = snprintf(output, mlen, "TRACE %s %s\r\n",
			params, httpver);

	for (size_t i = 0; i < http_headers.size; i++)
	{
		const char * const idx = http_headers.elements[i].index;
		const char * const val = http_headers.elements[i].value;

		if (outlen + strlen(idx) + strlen(val) + 4 >= mlen)
		{
			mlen += RWBUFSIZE;
			REALLOC(output, char, mlen);
		}
		outlen += sprintf(&output[outlen], "%s: %s\r\n", idx, val);
	}
	
	freeheaders(&http_headers);
	secprintf("%s 200 OK\r\n", httpver);
	stdheaders(false, false, false);
	secprintf("Content-length: %zu\r\n", outlen);
	secputs("Content-type: message/http\r\n\r\n");

	secputs(output);
	free(output);
	(void)params;
}

void
do_proxy(const char *proxy, const char *params)
{
#ifdef		HAVE_CURL
	CURL	*handle = curl_easy_init();
	char	*request, *p;

	if ((p = strstr(proxy, ":443")) || (p = strstr(proxy, ":https")))
	{
		*p = '\0'; /* or libcurl will try host:https:443 */
		asprintf(&request, "https://%s%s", proxy, params);
		curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0);
	}
	else
		asprintf(&request, "http://%s%s", proxy, params);
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
	persistent = false; headers = 10; /* force HTTP/1.0 */

	if (curl_easy_perform(handle))
		xserror(500, "Internal forwarding error");
	else
		logrequest(params, 0);
	free(request);
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
	FILE		*mime;

	if (!base)
		while (ftype)
		{
			ftypes	*temp;

			temp = ftype->next;
			free(ftype);
			ftype = temp;
		}
	while (lftype)
	{
		ftypes	*temp;

		temp = lftype->next;
		free(lftype);
		lftype = temp;
	}
	lftype = NULL;

	/* local block */
	{
		const char * const	mimepath = base
			? find_file(orgbase, base, ".mimetypes")
			: calcpath(MIME_TYPES);

		if (!mimepath || !(mime = fopen(mimepath, "r")))
		{
			if (!base)
				warn("fopen(`%s' [read])", mimepath);
			return;
		}
	}

	/* DECL */
	ftypes		*prev = NULL, *new = NULL;
	char		line[LINEBUFSIZE];

	while (fgets(line, LINEBUFSIZE, mime))
	{
		char	*name, *ext, *comment, *p;

		if ((comment = strchr(line, '#')))
			*comment = 0;
		p = line;
		for (name = strsep(&p, " \t\n"); (ext = strsep(&p, " \t\n")); )
		{
			if (!*ext)
				continue;
			MALLOC(new, ftypes, 1);
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
	const	char	*path;
	FILE		*methods;

	while (ctype)
	{
		ctypes	*temp;

		temp = ctype->next;
		free(ctype);
		ctype = temp;
	}
	path = calcpath(COMPRESS_METHODS);
	if (!(methods = fopen(path, "r")))
	{
		warn("fopen(`%s' [read])", path);
		return;
	}

	/* DECL */
	ctypes		*prev, *new;
	char		line[LINEBUFSIZE];

	prev = NULL;
	while (fgets(line, LINEBUFSIZE, methods))
	{
		char	*end, *comment;

		if ((comment = strchr(line, '#')))
			*comment = 0;
		end = line + strlen(line);
		while ((end > line) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (line == end)
			continue;
		MALLOC(new, ctypes, 1);
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
	FILE		*methods;

	if (orgbase && base)
	{
		char	*cffile;

		while (litype)
			{ ctypes *n = litype->next; free(litype); litype = n; }
		if (ditype)
			{ free(ditype); ditype = NULL; }
		if (!(cffile = find_file(orgbase, base, ".xsscripts")) ||
				!(methods = fopen(cffile, "r")))
			return;
	}
	else
	{
		while (itype)
			{ ctypes *n = itype->next; free(itype); itype = n; }
		if (!(methods = fopen(calcpath(SCRIPT_METHODS), "r")))
			/* missing script.methods is not fatal */
			return;
	}

	/* DECL */
	ctypes		*prev, *new;
	char		line[LINEBUFSIZE];

	prev = NULL;
	while (fgets(line, LINEBUFSIZE, methods))
	{
		char	*end, *comment;

		if ((comment = strchr(line, '#')))
			*comment = 0;
		end = line + strlen(line);
		while ((end > line) && (*(end - 1) <= ' '))
			*(--end) = 0;
		if (line == end)
			continue;
#ifndef		HAVE_PERL
		if (!strncmp(line, "internal:perl", 13))
			continue;
#endif		/* HAVE_PERL */
#ifndef		HAVE_PYTHON
		if (!strncmp(line, "internal:python", 15))
			continue;
#endif		/* HAVE_PYTHON */
		MALLOC(new, ctypes, 1);
		if (sscanf(line, "%s %s", new->prog, new->ext) != 2)
			errx(1, "Unable to parse `%s' in script types", line);
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
	fclose(methods);
}

static bool
getfiletype(bool print)
{
	const	ftypes	* const flist[] = { lftype, ftype };
	const	int	flen = sizeof(flist) / sizeof(ftypes *);
	const	char	*ext;

	if (cfvalues.mimetype || !(ext = strrchr(orig_filename, '.')) || !(*(++ext)))
	{
		if (!cfvalues.mimetype)
		{
			cfvalues.mimetype = strdup("application/octet-stream");
			return false;
		}
		else
			return !strcasecmp(cfvalues.mimetype, "text/html");
	}

	for (int i = 0; i < flen; i++)
	{
		for (const ftypes *search = flist[i]; search; search = search->next)
		{
			if (strcasecmp(ext, search->ext))
				continue;
			if (print)
			{
				size_t	len = strlen(search->name) + 1;

				if (cfvalues.mimetype)
					free(cfvalues.mimetype);
				MALLOC(cfvalues.mimetype, char, len);
				strlcpy(cfvalues.mimetype, search->name, len);

				if (!cfvalues.charset &&
					!strncmp(cfvalues.mimetype, "text/", 5))
				{
					/* only force default charset for
					 * textfiles
					 */
					cfvalues.charset = strdup(
						config.defaultcharset
						? config.defaultcharset
						: "us-ascii");
				}
			}
			return !strcasecmp(search->name, "text/html");
		}
	}
	if (print)
		cfvalues.mimetype = strdup("application/octet-stream");
	return false;
}

