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
#include	<string.h>
#include	<stdio.h>
#include	<errno.h>
#include	<netdb.h>
#ifdef		HAVE_TIME_H
#ifdef		SYS_TIME_WITH_TIME
#include	<time.h>
#endif		/* SYS_TIME_WITH_TIME */
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
#include	"getopt.h"
#include	"string.h"

#ifdef		__linux__
extern	char	*tempnam(const char *, const char *);
#endif		/* __linux__ */

/* This is for HP/UX */
#ifdef		HPUX
#ifndef		NOFORWARDS
extern	int	setpriority PROTO((int, int, int));
#endif		/* NOFORWARDS */
#endif		/* HPUX */

/* Global variables */

int		port, headers, localmode, netbufind, netbufsiz, readlinemode,
		headonly, postonly;
static	int	sd, reqs, number, mainhttpd = 1;
gid_t		group_id, origegid;
uid_t		user_id, origeuid;
char		netbuf[MYBUFSIZ], remotehost[MAXHOSTNAMELEN], orig[MYBUFSIZ],
		currenttime[80], dateformat[MYBUFSIZ], real_path[XS_PATH_MAX],
		thishostname[MAXHOSTNAMELEN], version[16], error_path[XS_PATH_MAX],
		access_path[XS_PATH_MAX], refer_path[XS_PATH_MAX], rootdir[XS_PATH_MAX],
		total[XS_PATH_MAX], name[XS_PATH_MAX];
static	char	browser[MYBUFSIZ], referer[MYBUFSIZ], outputbuffer[SENDBUFSIZE],
		thisdomain[MAXHOSTNAMELEN], message503[MYBUFSIZ],
		*startparams;
FILE		*access_log = NULL, *refer_log = NULL;
time_t		modtime;
#ifdef		INET6
static	struct	in6_addr	thisaddress6;
#else		/* INET6 */
static	struct	in_addr	thisaddress;
#endif		/* INET6 */
#ifdef		HANDLE_SSL
int		do_ssl;
SSL_CTX	*ssl_ctx;
SSL		*ssl;
#endif		/* HANDLE_SSL */

/* Static arrays */

static	char	six2pr[64] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

/* Prototypes */

#ifndef		NOFORWARDS
static	VOID	filedescrs		PROTO((void));
static	VOID	detach			PROTO((void));
static	VOID	child_handler		PROTO((int));
static	VOID	term_handler		PROTO((int));
static	VOID	open_logs		PROTO((int));
static	VOID	core_handler		PROTO((int));
static	VOID	set_signals		PROTO((void));

static	int	hexdigit		PROTO((int));
static	int	decode			PROTO((char *));

static	VOID	uudecode		PROTO((char *));

static	VOID	process_request		PROTO((void));

static	VOID	setup_environment	PROTO((void));
static	VOID	standalone_main		PROTO((void));
#endif		/* NOFORWARDS */

extern	VOID
stdheaders DECL3(int, lastmod, int, texthtml, int, endline)
{
	setcurrenttime();
	secprintf("Date: %s\r\nServer: %s\r\n", currenttime, SERVER_IDENT);
	if (headers >= 11)
		secprintf("Connection: close\r\n");
	if (lastmod)
		secprintf("Last-modified: %s\r\nExpires: %s\r\n",
			currenttime, currenttime);
	if (texthtml)
		secprintf("Content-type: text/html\r\n");
	if (endline)
		secprintf("\r\n");
}

static	VOID
filedescrs DECL0
{
	close(0); if (open(BITBUCKETNAME, O_RDONLY, 0) != 0)
		err(1, "Cannot open fd 0 (%s)", BITBUCKETNAME);
	if (dup2(0, 1) != 1)
		err(1, "Cannot dup2() fd 1");
}

static	VOID
detach DECL0
{
	pid_t		x;

	if (chdir("/"))
		err(1, "chdir(`/')");
	if ((x = fork()) > 0)
		exit(0);
	else if (x == -1)
		err(1, "fork()");
#ifdef		HAVE_SETSID
	if (setsid() == -1)
		err(1, "setsid() failed");
#else		/* Not HAVE_SETSID */
	if (setpgrp(getpid(), 0)) == -1)
		err(1, "setpgrp() failed");
#endif		/* HAVE_SETSID */
}

extern	VOID
setcurrenttime DECL0
{
	time_t		thetime;

	time(&thetime);
	strftime(currenttime, sizeof(currenttime),
		"%a, %d %b %Y %T GMT", gmtime(&thetime));
}

static	VOID
child_handler DECL1(int, sig)
{
#ifdef		NeXT
	union	wait	status;
#else		/* Not NeXT */
	int		status;
#endif		/* NeXT */

	while (wait3(&status, WNOHANG, NULL) > 0)
		/* NOTHING */;
	set_signals();
}

static	VOID
term_handler DECL1(int, sig)
{
	if (mainhttpd)
	{
		setcurrenttime();
		fprintf(stderr, "[%s] Received signal %d, shutting down...\n",
			currenttime, sig);
		fflush(stderr);
		mainhttpd = 0;
		killpg(0, SIGTERM);
	}
	exit(0);
}

static	VOID
open_logs DECL1(int, sig)
{
	FILE		*pidlog;
	char		buffer[XS_PATH_MAX];
	uid_t		savedeuid;
	gid_t		savedegid;
	int		tempfile;

	set_signals();
	savedeuid = savedegid = -1;
	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); setegid(origegid);
	}
	if (mainhttpd)
	{
		snprintf(buffer, XS_PATH_MAX, calcpath(PID_PATH));
		buffer[XS_PATH_MAX-1] = '\0';
		remove(buffer);
		if ((pidlog = fopen(buffer, "w")))
		{
			fprintf(pidlog, "%ld\n", (long)getpid());
			fprintf(pidlog, "%s\n", startparams);
			fclose(pidlog);
		}
		signal(SIGHUP, SIG_IGN); killpg(0, SIGHUP);
	}

	if (access_log)
		fclose(access_log);
	if (!(access_log = fopen(access_path, "a")))
		err(1, "fopen(`%s' [append])", access_path);
#ifndef		SETVBUF_REVERSED
	setvbuf(access_log, NULL, _IOLBF, 0);
#else		/* Not not SETVBUF_REVERSED */
	setvbuf(access_log, _IOLBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */

	fflush(stderr);
	close(2);
	if ((tempfile = open(error_path, O_CREAT | O_APPEND | O_WRONLY,
		S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP)) < 0)
		err(1, "open(`%s' [append])", error_path);
	if (tempfile != 2)
	{
		if (dup2(tempfile, 2) == -1)
			err(1, "dup2() failed");
		close(tempfile);
	}

	if (refer_log)
		fclose(refer_log);
	if (!(refer_log = fopen(refer_path, "a")))
		err(1, "fopen(`%s' [append])", refer_path);
#ifndef		SETVBUF_REVERSED
	setvbuf(refer_log, NULL, _IOLBF, 0);
#else		/* Not not SETVBUF_REVERSED */
	setvbuf(refer_log, _IOLBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */

	if (mainhttpd)
	{
		setcurrenttime();
		fprintf(stderr, "[%s] httpd: Successful restart\n",
			currenttime);
	}
	loadfiletypes();
#ifdef		HANDLE_COMPRESSED
	loadcompresstypes();
#endif		/* HANDLE_COMPRESSED */
#ifdef		HANDLE_SCRIPT
	loadscripttypes();
#endif		/* HANDLE_SCRIPT */
#ifdef		HANDLE_SSL
	loadssl();
#endif		/* HANDLE_SSL */
	set_signals();
	if (!origeuid)
	{
		if (seteuid(savedeuid) == -1)
			err(1, "seteuid()");
		if (setegid(savedegid) == -1)
			err(1, "setegid()");
	}
}

extern	VOID
alarm_handler DECL1(int, sig)
{
	alarm(0); setcurrenttime();
	fprintf(stderr, "[%s] httpd: Send timed out for `%s'\n",
		currenttime, remotehost[0] ? remotehost : "(none)");
	exit(1);
}

static	VOID
core_handler DECL1(int, sig)
{
	const	char	*env;

	alarm(0); setcurrenttime();
	env = getenv("QUERY_STRING");
	fprintf(stderr, "[%s] httpd(pid %ld): FATAL SIGNAL %d [from: `%s' req: `%s' params: `%s' referer: `%s']\n",
		currenttime, (long)getpid(), sig,
		remotehost[0] ? remotehost : "(none)",
		orig[0] ? orig : "(none)", env ? env : "(none)",
		referer[0] ? referer : "(none)");
	exit(1);
}

static	VOID
set_signals DECL0
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

extern	VOID
error DECL1C(char *, message)
{
	const	char	*env;

	alarm(180); setcurrenttime();
	env = getenv("QUERY_STRING");
	fprintf(stderr, "[%s] httpd(pid %ld): %s [from: `%s' req: `%s' params: `%s' referer: `%s']\n",
		currenttime, (long)getpid(), message,
		remotehost[0] ? remotehost : "(none)",
		orig[0] ? orig : "(none)", env ? env : "(none)",
		referer[0] ? referer : "(none)");
	if (headers)
	{
		secprintf("%s %s\r\n", version, message);
		stdheaders(1, 1, 1);
	}
	if (!headonly)
	{
		secprintf("\r\n<HTML><HEAD><TITLE>%s</TITLE></HEAD><BODY>\n",
			message);
		secprintf("<H1>%s</H1></BODY></HTML>\n", message);
	}
	fflush(stdout); fflush(stderr); alarm(0);
}

extern	VOID
redirect DECL2C_(char *, redir, int, permanent)
{
	const	char	*env;

	env = getenv("QUERY_STRING");
	if (headers)
	{
		secprintf("%s %s moved\r\nLocation: %s\r\n", version,
			permanent ? "301 Permanently" : "302 Temporarily",
			redir);
		stdheaders(1, 1, 1);
	}
	if (!headonly)
	{
		secprintf("\r\n<HTML><HEAD><TITLE>Document has moved</TITLE></HEAD>");
		secprintf("<BODY>\n<H1>Document has moved</H1>This document has ");
		secprintf("%smoved to <A HREF=\"%s%s%s\">%s</A>.</BODY></HTML>\n",
			permanent ? "permanently " : "", redir,
			env ? "?" : "", env ? env : "", redir);
	}
	fflush(stdout);
}

static	int
hexdigit DECL1(int, ch)
{
	const	char	*temp, *hexdigits = "0123456789ABCDEF";

	if ((temp = strchr(hexdigits, toupper(ch))))
		return(temp - hexdigits);
	else
	{
		error("500 Invalid `percent' parameters");
		return(-1);
	}
}

static	int
decode DECL1(char *, str)
{
	char		*posd, chr;
	const	char	*poss;
	int		top, bottom;

	poss = posd = str;
	while ((chr = *poss))
	{
		if (chr != '%')
		{
			if (chr == '?')
			{
				bcopy(poss, posd, strlen(poss) + 1);
				return(ERR_NONE);
			}
			*(posd++) = chr;
			poss++;
		} else
		{
			if ((top = hexdigit((int)poss[1])) == -1)
				return(ERR_QUIT);
			if ((bottom = hexdigit((int)poss[2])) == -1)
				return(ERR_QUIT);
			*(posd++) = (top << 4) + bottom;
			poss += 3;
		}
	}
	*posd = 0;
	return(ERR_NONE);
}

static	VOID
uudecode DECL1(char *, buffer)
{
	unsigned char	pr2six[256], bufplain[32], *bufout = bufplain;
	int		nbytesdecoded, j, nprbytes;
	char		*bufin = buffer;

	for (j = 0; j < 256; j++)
		pr2six[j] = 64;
	for (j = 0; j < 64; j++)
		pr2six[(int)six2pr[j]] = (unsigned char)j;
	bufin = buffer;
	while (pr2six[(int)*(bufin++)] <= 63)
		/* NOTHING HERE */;
	nprbytes = bufin - buffer - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;
	bufin = buffer;
	while (nprbytes > 0)
	{
		*(bufout++) = (unsigned char) ((pr2six[(int)*bufin] << 2) |
			(pr2six[(int)bufin[1]] >> 4));
		*(bufout++) = (unsigned char) ((pr2six[(int)bufin[1]] << 4) |
			(pr2six[(int)bufin[2]] >> 2));
		*(bufout++) = (unsigned char) ((pr2six[(int)bufin[2]] << 6) |
			(pr2six[(int)bufin[3]]));
		bufin += 4; nprbytes -= 4;
	}
   
	if (nprbytes & 3)
	{
		if (pr2six[(int)*(bufin - 2)] > 63)
			nbytesdecoded -= 2;
		else
			nbytesdecoded--;
	}
	if (nbytesdecoded)
		bcopy((char *)bufplain, buffer, nbytesdecoded);
	buffer[nbytesdecoded] = 0;
}

extern	int
check_auth DECL1(FILE *, authfile)
{
	char		*search, line[MYBUFSIZ], compare[MYBUFSIZ], *find;
	const	char	*env;

	if (!(env = getenv("AUTH_TYPE")))
	{
		if (headers)
		{
			secprintf("%s 401 Unauthorized\r\n", version);
			secprintf("WWW-authenticate: basic realm=\"this page\"\r\n");
			stdheaders(1, 1, 1);
		}
		secprintf("\r\n<HTML><HEAD><TITLE>Unauthorized</TITLE></HEAD>\n");
		secprintf("<BODY><H1>Unauthorized</H1>\nYour client does not ");
		secprintf("understand authentication.\n</BODY></HTML>\n");
		fclose(authfile); return(1);
	}
	strncpy(line, env, MYBUFSIZ - 1); line[MYBUFSIZ - 1] = 0;
	find = line + strlen(line);
	while ((find > line) && (*(find - 1) < ' '))
		*(--find) = 0;
	for (search = line; *search && (*search != ' ') &&
		(*search != 9); search++) ;
	while ((*search == 9) || (*search == ' '))
		search++;
	uudecode(search);
	if ((find = strchr(search, ':')))
	{
		*find = 0;
		setenv("REMOTE_USER", search, 1);
		*find = ':';
		setenv("REMOTE_PASSWORD", find + 1, 1);
		xs_encrypt(find + 1);
	}
	while (fgets(compare, MYBUFSIZ, authfile))
	{
		compare[strlen(compare) - 1] = 0;
		if (!strcmp(compare + 1, search))
		{
			fclose(authfile); return(0);
		}
	}
	fclose(authfile);
	server_error("401 Wrong user/password combination", "UNAUTHORIZED");
	return(1);
}

extern	char	*
escape DECL1C(char *, what)
{
	char		*escapebuf, *w;

	if (!(w = escapebuf = (char *)malloc(BUFSIZ)))
		return(NULL);
	while (*what && ((w - escapebuf) < (BUFSIZ - 10)))
	{
		switch(*what)
		{
		case '<':
			strcpy(w, "&lt;"); w += 4;
			break;
		case '>':
			strcpy(w, "&gt;"); w += 4;
			break;
		case '&':
			strcpy(w, "&amp;"); w += 5;
			break;
		case '"':
			strcpy(w, "&quot;"); w += 6;
			break;
		default:
			*(w++) = *what;
			break;
		}
		what++;
	}
	*w = 0;
	return(escapebuf);
}

extern	VOID
server_error DECL2CC(char *, readable, char *, cgi)
{
	struct	stat		statbuf;
	const	struct	passwd	*userinfo;
	char			*search, cgipath[XS_PATH_MAX], base[XS_PATH_MAX],
				*escaped;
	const	char		*env;

	if (headonly)
	{
		error(readable);
		return;
	}
	setenv("ERROR_CODE", cgi, 1);
	setenv("ERROR_READABLE", readable, 1);
	setenv("ERROR_URL", orig, 1);
	setenv("ERROR_URL_EXPANDED", convertpath(orig), 1);
	escaped = escape(orig);
	setenv("ERROR_URL_ESCAPED", escaped ? escaped : "", 1);
	if (escaped)
		free(escaped);
	env = getenv("QUERY_STRING");
	if (real_path[1] == '~')
	{
		if ((search = strchr(real_path + 2, '/')))
			*search = 0;
		if ((userinfo = getpwnam(real_path + 2)))
		{
			if (search)
				*search = '/';
			if (!transform_user_dir(base, userinfo, 0))
			{
				snprintf(cgipath, XS_PATH_MAX, "%s/%s/error",
					base, HTTPD_SCRIPT_ROOT);
				cgipath[XS_PATH_MAX-1] = '\0';
				if (!stat(cgipath, &statbuf))
				{
					snprintf(cgipath, XS_PATH_MAX, "/~%s/%s/error",
						userinfo->pw_name,
						HTTPD_SCRIPT_ROOT);
					cgipath[XS_PATH_MAX-1] = '\0';
					goto EXECUTE;
				}
			}
		}
		if (search)
			*search = '/';
	}
	strncpy(base, calcpath(HTTPD_SCRIPT_ROOT_P), XS_PATH_MAX);
	base[XS_PATH_MAX-1] = '\0';
	snprintf(cgipath, XS_PATH_MAX, "%s/error", base);
	cgipath[XS_PATH_MAX-1] = '\0';
	if (stat(cgipath, &statbuf))
		error(readable);
	else
	{
		snprintf(cgipath, XS_PATH_MAX, "/%s/error", HTTPD_SCRIPT_ROOT);
		cgipath[XS_PATH_MAX-1] = '\0';
		EXECUTE:
		setcurrenttime();
		fprintf(stderr, "[%s] httpd(pid %ld): %s [from: `%s' req: `%s' params: `%s' referer: `%s']\n",
			currenttime, (long)getpid(), readable,
			remotehost[0] ? remotehost : "(none)",
			orig[0] ? orig : "(none)", env ? env : "(none)",
			referer[0] ? referer : "(none)");
		do_script(cgipath, NULL, headers);
	}
}

size_t
secread(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (do_ssl && fd == 0)
		return SSL_read(ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return read(fd, buf, count);
}

size_t
secwrite(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (do_ssl)
		return SSL_write(ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return write(fd, buf, count);
}

size_t
secfwrite(void *buf, size_t size, size_t count, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (do_ssl)
		return SSL_write(ssl, buf, size), count;
	else
#endif		/* HANDLE_SSL */
		return fwrite(buf, size, count, stream);
}

size_t
secprintf(const char *format, ...)
{
	va_list	ap;
	char	buf[4096];

	va_start(ap, format);
	vsnprintf(buf, 4096, format, ap);
	va_end(ap);
#ifdef		HANDLE_SSL
	if (do_ssl)
		return SSL_write(ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return printf("%s", buf);
}

size_t
secfputs(char *buf, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (do_ssl)
		return SSL_write(ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return fputs(buf, stream);
}

extern	int
readline DECL2(int, sd, char *, buf)
{
	char		ch, *buf2;

	buf2 = buf; *buf2 = 0;
	do
	{
		if (netbufind >= netbufsiz)
		{
			TRYAGAIN:
			netbufsiz = secread(sd, netbuf,
				readlinemode ? MYBUFSIZ : 1);
			if (netbufsiz == -1)
			{
				if ((errno == EAGAIN) || (errno == EINTR))
				{
					mysleep(1); goto TRYAGAIN;
				}
				fprintf(stderr, "[%s] httpd: readline(): %s [%d]\n",
					currenttime, strerror(errno), sd);
				if (sd == 0)
					error("503 Unexpected network error");
				return(ERR_QUIT);
			}
			if (netbufsiz == 0)
			{
				if (*buf)
				{
					*buf2 = 0;
					return(ERR_NONE);
				}
				if (sd == 0)
					error("503 You closed the connection!");
				return(ERR_QUIT);
			}
			netbufind = 0;
		}
		ch = *(buf2++) = netbuf[netbufind++];
	} while ((ch != '\n') && (buf2 < (buf + MYBUFSIZ - 64)));
	*buf2 = 0;
	return(ERR_NONE);
}

static	VOID
process_request DECL0
{
	char		line[MYBUFSIZ], extra[MYBUFSIZ], *temp,
			*params, *url, *ver;
	int		index, readerror;
	size_t		size;

	strcpy(version, "HTTP/0.9");
	strcpy(dateformat, "%a %b %e %H:%M:%S %Y");
	total[0] = orig[0] = name[0] = referer[0] = line[0] =
		real_path[0] = browser[0] = 0;
	netbufsiz = netbufind = headonly = postonly = headers = index = 0;
	unsetenv("CONTENT_LENGTH"); unsetenv("AUTH_TYPE");
	unsetenv("CONTENT_TYPE"); unsetenv("QUERY_STRING");
	unsetenv("ERROR_CODE"); unsetenv("ERROR_READABLE");
	unsetenv("ERROR_URL"); unsetenv("ERROR_URL_ESCAPED");
	unsetenv("ERROR_URL_EXPANDED"); unsetenv("REMOTE_USER");
	unsetenv("REMOTE_PASSWORD");
	unsetenv("HTTP_REFERER"); unsetenv("HTTP_COOKIE");
	unsetenv("HTTP_ACCEPT"); unsetenv("HTTP_ACCEPT_ENCODING");
	unsetenv("HTTP_ACCEPT_LANGUAGE"); unsetenv("HTTP_HOST");
	unsetenv("HTTP_NEGOTIONATE"); unsetenv("HTTP_PRAGMA");
	unsetenv("HTTP_CLIENT_IP"); unsetenv("HTTP_VIA");
	unsetenv("IF_MODIFIED_SINCE"); unsetenv("IF_UNMODIFIED_SINCE");
	unsetenv("IF_RANGE");
	unsetenv("SSL_CIPHER");


	alarm(180); errno = 0;
#ifdef		HANDLE_SSL
	if (do_ssl)
		setenv("SSL_CIPHER", SSL_get_cipher(ssl), 1);
	if (readerror = ERR_get_error()) {
		fprintf(stderr, "SSL Error: %s\n", ERR_reason_error_string(readerror));
		error("400 SSL Error");
		return;
	}
#endif		/* HANDLE_SSL */
	readerror = secread(0, line, 1);
	if (readerror == 1)
		readerror = secread(0, line + 1, 1);
	if (readerror == 1)
		readerror = secread(0, line + 2, 1);
	if (readerror == 1)
		readerror = secread(0, line + 3, 1);
	if (readerror != 1)
	{
		if (readerror == -1)
			fprintf(stderr, "[%s] Request line: read() failed: %s\n",
				currenttime, strerror(errno));
		else
			fprintf(stderr, "[%s] Request line: read() got no input\n",
				currenttime);
		error("400 Unable to read begin of request line");
		return;
	}
	readlinemode = strncasecmp("POST", line, 4);
	if (readline(0, line + 4) == ERR_QUIT)
	{
		error("400 Unable to read request line");
		return;
	}
	size = strlen(line);
	bzero(line + size, 16);
	temp = orig + strlen(orig);
	while ((temp > orig) && (*(temp - 1) <= ' '))
		*(--temp) = 0;
	url = line;
	while (*url && (*url > ' '))
		url++;
	*(url++) = 0;
	while (*url <= ' ')
		url++;
	ver = url;
	while (*ver && (*ver > ' '))
		ver++;
	*(ver++) = 0;
	while (*ver <= ' ')
		ver++;
	temp = ver;
	while (*temp && (*temp > ' '))
		temp++;
	*temp = 0;
	if (!strncasecmp(ver, "HTTP/", 5))
	{
		if (!strncmp(ver + 5, "1.0", 3))
		{
			headers = 10;
			strcpy(version, "HTTP/1.0");
		}
		else
		{
			headers = 11;
			strcpy(version, "HTTP/1.1");
		}
		setenv("SERVER_PROTOCOL", version, 1);
		while (1)
		{
			char		*param, *end;

			if (readline(0, extra) == ERR_QUIT)
			{
				error("400 Unable to read HTTP headers");
				return;
			}
			if (extra[0] <= ' ')
				break;
			if (!(param = strchr(extra, ':')))
				continue;
			*(param++) = 0;
			while ((*param == ' ') || (*param == 9))
				param++;
			end = param + strlen(param);
			while ((end > param) && (*(end - 1) <= ' '))
				*(--end) = 0;

			if (!strcasecmp("Content-length", extra))
				setenv("CONTENT_LENGTH", param, 1);
			else if (!strcasecmp("Content-type", extra))
				setenv("CONTENT_TYPE", param, 1);
			else if (!strcasecmp("User-agent", extra))
			{
				strncpy(browser, param, MYBUFSIZ - 1);
				browser[MYBUFSIZ - 1] = 0;
				setenv("USER_AGENT", browser, 1);
				setenv("HTTP_USER_AGENT", browser, 1);
				strtok(browser, "/");
				for (temp = browser; *temp; temp++)
					*temp = tolower(*temp);
				*browser = toupper(*browser);
				setenv("USER_AGENT_SHORT", browser, 1);
			} else if (!strcasecmp("Referer", extra))
			{
				strncpy(referer, param, MYBUFSIZ-16);
				while (referer[0] &&
					referer[strlen(referer) - 1] <= ' ')
					referer[strlen(referer) - 1] = 0;
				setenv("HTTP_REFERER", referer, 1);
			} else if (!strcasecmp("Authorization", extra))
				setenv("AUTH_TYPE", param, 1);
			else if (!strcasecmp("Cookie", extra))
				setenv("HTTP_COOKIE", param, 1);
			else if (!strcasecmp("Accept", extra))
				setenv("HTTP_ACCEPT", param, 1);
			else if (!strcasecmp("Accept-encoding", extra))
				setenv("HTTP_ACCEPT_ENCODING", param, 1);
			else if (!strcasecmp("Accept-language", extra))
				setenv("HTTP_ACCEPT_LANGUAGE", param, 1);
			else if (!strcasecmp("Host", extra))
				setenv("HTTP_HOST", param, 1);
			else if (!strcasecmp("Negotiate", extra))
				setenv("HTTP_NEGOTIATE", param, 1);
			else if (!strcasecmp("Pragma", extra))
				setenv("HTTP_PRAGMA", param, 1);
			else if (!strcasecmp("Client-ip", extra))
				setenv("HTTP_CLIENT_IP", param, 1);
			else if (!strcasecmp("X-Forwarded-For", extra))
				/* People should use the HTTP/1.1 variant */
				setenv("HTTP_CLIENT_IP", param, 1);
			else if (!strcasecmp("Via", extra))
				setenv("HTTP_VIA", param, 1);
			else if (!strcasecmp("If-modified-since", extra))
				setenv("IF_MODIFIED_SINCE", param, 1);
			else if (!strcasecmp("If-unmodified-since", extra))
				setenv("IF_UNMODIFIED_SINCE", param, 1);
			else if (!strcasecmp("If-range", extra))
				setenv("IF_RANGE", param, 1);

		}
	} else
		setenv("SERVER_PROTOCOL", version, 1);

	if (!getenv("CONTENT_LENGTH"))
		setenv("CONTENT_LENGTH", "0", 1);
	if (!browser[0])
	{
		setenv("USER_AGENT", "UNKNOWN", 1);
		setenv("HTTP_USER_AGENT", "UNKNOWN", 1);
		setenv("USER_AGENT_SHORT", "UNKNOWN", 1);
	}

	alarm(0);
	params = url;
	if (decode(params))
		return;

	size = strlen(params);
	bzero(params + size, 16);
	bcopy(params, orig, size + 16);

	if (referer[0] &&
		(!thisdomain[0] || !strcasestr(referer, thisdomain)))
		fprintf(refer_log, "%s -> %s\n", referer, params);

	if (headers >= 11 && !(getenv("HTTP_HOST")))
	{
		server_error("400 Bad Request", "BAD_REQUEST");
		return;
	}
	if (params[0] != '/' && strcmp("OPTIONS", line))
	{
		server_error("400 Relative URL's are not supported",
			"NO_RELATIVE_URLS");
		return;
	}

	setenv("REQUEST_METHOD", line, 1);
	if (!strcmp("GET", line))
		do_get(params);
	else if (!strcmp("HEAD", line))
		do_head(params);
	else if (!strcmp("POST", line))
		do_post(params);
	else if (!strcmp("OPTIONS", line))
		do_options(params);
	/*
	else if (!strcmp("PUT", line))
		do_put(params);
	else if (!strcmp("DELETE", line))
		do_delete(params);
	else if (!strcmp("TRACE", line))
		do_trace(params);
	*/
	else
		server_error("400 Unknown method", "UNKNOWN_METHOD");
}

static	VOID
standalone_main DECL0
{
	int			csd = 0, count, temp;
	size_t			clen;
#ifdef		INET6
	struct	sockaddr_in6	sa6_server, sa6_client;
#else		/* INET 6 */
	struct	sockaddr_in	sa_server, sa_client;
#endif		/* INET 6 */
	const	struct	hostent	*remote;
	pid_t			*childs, pid;
	struct	rlimit		limit;

	/* Speed hack */
	gethostbyname("localhost");

	detach(); open_logs(0);

	setprocname("xs(MAIN): Initializing deamons...");
#ifdef		INET6
	if ((sd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1)
#else		/* INET 6 */
	if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
#endif		/* INET 6 */
		err(1, "socket()");

	temp = 1;
	if ((setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &temp, sizeof(temp))) == -1)
		err(1, "setsockopt(REUSEADDR)");

	temp = 1;
	if ((setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &temp, sizeof(temp))) == -1)
		err(1, "setsockopt(KEEPALIVE)");

#ifdef		INET6
	memset(&sa6_server, 0, sizeof(sa6_server));
	sa6_server.sin6_family = AF_INET6;
	sa6_server.sin6_addr = thisaddress6;
	sa6_server.sin6_port = htons(port);
	if (bind(sd, (struct sockaddr *)&sa6_server, sizeof(sa6_server)) == -1)
		err(1, "bind()");
#else		/* INET6 */
	memset(&sa_server, 0, sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr = thisaddress;
	sa_server.sin_port = htons(port);
	if (bind(sd, (struct sockaddr *)&sa_server, sizeof(sa_server)) == -1)
		err(1, "bind()");
#endif		/* INET6 */

	if (listen(sd, MAXLISTEN))
		err(1, "listen()");

#ifdef		RLIMIT_NPROC
	limit.rlim_max = limit.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_NPROC, &limit);
#endif		/* RLIMIT_NPROC */
#ifdef		RLIMIT_CPU
	limit.rlim_max = limit.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_CPU, &limit);
#endif		/* RLIMIT_CPU */

	set_signals(); reqs = 0;
	if (!(childs = (pid_t *)malloc(sizeof(pid_t) * number)))
		errx(1, "malloc() failed");

	for (count = 0; count < number; count++)
	{
		switch(pid = fork())
		{
		case -1:
			warn("fork() failed");
			killpg(0, SIGTERM);
			exit(1);
		case 0:
			mainhttpd = 0;
			goto CHILD;
		default:
			childs[count] = pid;
		}
	}

	fflush(stdout);
	while (1)
	{
		setprocname("xs(MAIN): Waiting for dead children");
		while (mysleep(30))
			/* NOTHING HERE */;
		setprocname("xs(MAIN): Searching for dead children");
		for (count = 0; count < number; count++)
		{
			if (kill(childs[count], 0))
			{
				fflush(stdout);
				switch(pid = fork())
				{
				case -1:
					fprintf(stderr,
						"[%s] httpd: fork() failed: %s\n",
						currenttime, strerror(errno));
					break;
				case 0:
					mainhttpd = 0;
					goto CHILD;
				default:
					childs[count] = pid;
				}
			}
		}
	}

	CHILD:
#ifndef		SETVBUF_REVERSED
	setvbuf(stdout, outputbuffer, _IOFBF, SENDBUFSIZE);
#else		/* Not not SETVBUF_REVERSED */
	setvbuf(stdout, _IOFBF, outputbuffer, SENDBUFSIZE);
#endif		/* SETVBUF_REVERSED */
	while (1)
	{
		struct	linger	sl;

		/* (in)sanity check */
		if (count > number || count < 0)
		{
			const	char	*env;

			env = getenv("QUERY_STRING");
			fprintf(stderr, "[%s] httpd(pid %ld): MEMORY CORRUPTION [from: `%s' req: `%s' params: `%s' referer: `%s']\n",
				currenttime, (long)getpid(),
				remotehost[0] ? remotehost : "(none)",
				orig[0] ? orig : "(none)", env ? env : "(none)",
				referer[0] ? referer : "(none)");
			exit(1);
		}

		setprocname("xs(%d): [Reqs: %06d] Setting up myself to accept a connection",
			count + 1, reqs);
		if (!origeuid && (seteuid(origeuid) == -1))
			err(1, "seteuid(%ld) failed", (long)origeuid);
		if (!origeuid && (setegid(origegid) == -1))
			err(1, "setegid(%ld) failed", (long)origegid);
		filedescrs();
		setprocname("xs(%d): [Reqs: %06d] Waiting for a connection...",
			count + 1, reqs);
#ifdef		INET6
		clen = sizeof(sa6_client);
		csd = accept(sd, (struct sockaddr *)&sa6_client, &clen);
#else		/* INET 6 */
		clen = sizeof(sa_client);
		csd = accept(sd, (struct sockaddr *)&sa_client, &clen);
#endif		/* INET 6 */
		if (csd < 0)
		{
			if (errno == EINTR)
				child_handler(SIGCHLD);
			continue;
		}
		setprocname("xs(%d): [Reqs: %06d] accept() gave me a connection...",
			count + 1, reqs);
		if (fcntl(csd, F_SETFL, 0))
			warn("fcntl() in standalone_main");

		sl.l_onoff = 1; sl.l_linger = 600;
		setsockopt(csd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#if 0
#ifndef		__linux__
#ifndef		INET6
#ifdef		SO_SNDBUF
		temp = SENDBUFSIZE + 64;
		setsockopt(csd, SOL_SOCKET, SO_SNDBUF, &temp, sizeof(temp));
#endif		/* SO_SNDBUF */
#ifdef		SO_RCVBUF
		temp = 512;
		setsockopt(csd, SOL_SOCKET, SO_RCVBUF, &temp, sizeof(temp));
#endif		/* SO_RCVBUF */
#endif		/* INET6 */
#endif		/* __linux__ */
#endif		/* 0 */

		dup2(csd, 0); dup2(csd, 1);
#ifdef		HANDLE_SSL
		if (!do_ssl)
#endif		/* HANDLE_SSL */
			close(csd);

#ifndef		SETVBUF_REVERSED
		setvbuf(stdin, NULL, _IONBF, 0);
#else		/* Not not SETVBUF_REVERSED */
		setvbuf(stdin, _IONBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */

#ifdef		INET6
		inet_ntop(AF_INET6, (void *)sa6_client.sin6_addr.s6_addr, remotehost,
				sizeof(remotehost));
		setenv("REMOTE_ADDR", remotehost, 1);
#else		/* INET 6 */
		setenv("REMOTE_ADDR", inet_ntoa(sa_client.sin_addr), 1);
#endif		/* INET 6 */
#ifdef		INET6
		if ((remote = gethostbyaddr((char *)&sa6_client.sin6_addr,
			sizeof(struct in6_addr), sa6_client.sin6_family)))
#else		/* INET 6 */
		if ((remote = gethostbyaddr((char *)&sa_client.sin_addr,
			sizeof(struct in_addr), sa_client.sin_family)))
#endif		/* INET 6 */
		{
			strncpy(remotehost, remote->h_name, MAXHOSTNAMELEN);
			remotehost[MAXHOSTNAMELEN-1] = '\0';
			setenv("REMOTE_HOST", remotehost, 1);
		} else
		{
#ifdef		INET6
			inet_ntop(AF_INET6, (void *)(sa6_client.sin6_addr.s6_addr), remotehost,
					sizeof(remotehost));
#else		/* INET 6 */
			strncpy(remotehost, inet_ntoa(sa_client.sin_addr), MAXHOSTNAMELEN);
			remotehost[MAXHOSTNAMELEN-1] = '\0';
#endif		/* INET 6 */
			unsetenv("REMOTE_HOST");
		}
#ifdef		HANDLE_SSL
		if (do_ssl) {
			ssl = SSL_new(ssl_ctx);
			SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
			SSL_set_fd(ssl, csd);
			if (!SSL_accept(ssl)) {
				fprintf(stderr, "SSL flipped\n");
				secprintf("%s 500 Failed\r\nContent-type: text/plain\r\n\r\n",
					version);
				secprintf("SSL Flipped...\n");
				return;
			}
		}
#endif		/* HANDLE_SSL */
		setprocname("xs(%d): Connect from `%s'", count + 1, remotehost);
		setcurrenttime();
		if (message503[0])
		{
			alarm(180);
			secprintf("%s 503 Busy\r\nContent-type: text/plain\r\n\r\n", version);
			secprintf("%s\n", message503);
		} else
			process_request();
		alarm(0); reqs++;
#ifdef		HANDLE_SSL
		SSL_free(ssl);
		close(csd);
#endif		/* HANDLE_SSL */
		fflush(stdout); fflush(stdin); fflush(stderr);
	}
	/* NOTREACHED */
}

static	VOID
setup_environment DECL0
{
	char		buffer[16];

	setenv("SERVER_SOFTWARE", SERVER_IDENT, 1);
	setenv("SERVER_NAME", thishostname, 1);
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	snprintf(buffer, 16, "%d", port);
	buffer[15] = '\0';
	setenv("SERVER_PORT", buffer, 1);
	snprintf(buffer, 16, "%d", localmode);
	buffer[15] = '\0';
	setenv("LOCALMODE", buffer, 1);
	setenv("HTTPD_ROOT", rootdir, 1);
}

int
main DECL3(int, argc, char **, argv, char **, envp)
{
	const	struct	passwd	*userinfo;
	const	struct	group	*groupinfo;
	int			option, num, fport = 0;
#ifndef 	INET6
	const	struct	hostent	*hp;
#endif		/* INET6 */

	origeuid = geteuid(); origegid = getegid();
#ifdef		HAVE_SETPRIORITY
	if (setpriority(PRIO_PROCESS, (pid_t)0, PRIO_MAX))
		warn("setpriority");
#endif		/* HAVE_SETPRIORITY */

	for (num = option = 0; option < argc; option++)
		num += (1 + strlen(argv[option]));
	if (!(startparams = (char *)malloc(num)))
		errx(1, "Cannot malloc memory for startparams");
	*startparams = 0;
	for (option = 0; option < argc; option++)
	{
		strcat(startparams, argv[option]);
		if (option < argc - 1)
			strcat(startparams, " ");
	}

	port = 80; number = HTTPD_NUMBER; localmode = 1;
	strncpy(rootdir, HTTPD_ROOT, XS_PATH_MAX);
	rootdir[XS_PATH_MAX-1] = '\0';
	message503[0] = 0;
#ifdef		THISDOMAIN
	strncpy(thisdomain, THISDOMAIN, MAXHOSTNAMELEN);
	thisdomain[MAXHOSTNAMELEN-1] = '\0';
#else		/* Not THISDOMAIN */
	thisdomain[0] = 0;
#endif		/* THISDOMAIN */
#ifdef		INET6
	memcpy(thisaddress6.s6_addr, &in6addr_any, sizeof(in6addr_any));
#else		/* INET 6 */
	thisaddress.s_addr = htonl(INADDR_ANY);
#endif		/* INET 6 */
	if (gethostname(thishostname, MAXHOSTNAMELEN) == -1)
		errx(1, "gethostname() failed");
	if ((userinfo = getpwnam(HTTPD_USERID)))
		user_id = userinfo->pw_uid;
	else
		user_id = 32767;
	if ((groupinfo = getgrnam(HTTPD_GROUPID)))
		group_id = groupinfo->gr_gid;
	else
		group_id = 32766;
	if ((short)user_id == -1)
		err(1, "Check your password file: nobody may not have UID -1 or 65535.");
	if ((short)group_id == -1)
		err(1, "Check your group file: nogroup may not have GID -1 or 65535.");
	snprintf(access_path, XS_PATH_MAX, "%s/access_log", calcpath(HTTPD_LOG_ROOT));
	snprintf(error_path, XS_PATH_MAX, "%s/error_log", calcpath(HTTPD_LOG_ROOT));
	snprintf(refer_path, XS_PATH_MAX, "%s/referer_log", calcpath(HTTPD_LOG_ROOT));
	access_path[XS_PATH_MAX-1] = '\0';
	error_path[XS_PATH_MAX-1] = '\0';
	refer_path[XS_PATH_MAX-1] = '\0';
	while ((option = getopt(argc, argv, "a:d:g:l:m:n:p:r:su:A:R:E:")) != EOF)
	{
		switch(option)
		{
		case 'n':
			if ((number = atoi(optarg)) <= 0)
				errx(1, "Invalid number of processes");
			break;
		case 'p':
			if ((port = atoi(optarg)) <= 0)
				errx(1, "Invalid port number");
			fport = 1;
			break;
		case 's':
#ifdef		HANDLE_SSL
			if (!fport)
				port = 443;
			do_ssl = 1;
			/* override defaults */
			snprintf(access_path, XS_PATH_MAX,
				"%s/ssl_access_log", calcpath(HTTPD_LOG_ROOT));
			snprintf(error_path, XS_PATH_MAX,
				"%s/ssl_error_log", calcpath(HTTPD_LOG_ROOT));
			snprintf(refer_path, XS_PATH_MAX,
				"%s/ssl_referer_log", calcpath(HTTPD_LOG_ROOT));
			access_path[XS_PATH_MAX-1] = '\0';
			error_path[XS_PATH_MAX-1] = '\0';
			refer_path[XS_PATH_MAX-1] = '\0';
#else		/* HANDLE_SSL */
			errx(1, "SSL support not enabled at compile-time");
#endif		/* HANDLE_SSL */
			break;
		case 'u':
			if ((user_id = atoi(optarg)) > 0)
				break;
			if (!(userinfo = getpwnam(optarg)))
				errx(1, "Invalid user ID");
			user_id = userinfo->pw_uid;
			break;
		case 'g':
			if ((group_id = atoi(optarg)) > 0)
				break;
			if (!(groupinfo = getgrnam(optarg)))
				errx(1, "Invalid group ID");
			group_id = groupinfo->gr_gid;
			break;
		case 'd':
			if (*optarg != '/')
				errx(1, "The -d directory must start with a /");
			strncpy(rootdir, optarg, XS_PATH_MAX-1);
			rootdir[XS_PATH_MAX-1] = 0;
			break;
		case 'a':
#ifdef		INET6
			/* TODO -Koresh */
			strncpy(thishostname, optarg, MAXHOSTNAMELEN);
#else		/* INET6 */
			if ((thisaddress.s_addr = inet_addr(optarg)) == -1)
			{
				if ((hp = gethostbyname(optarg)))
					memcpy((char *)&thisaddress,
						hp->h_addr, hp->h_length);
				else
					errx(1, "gethostbyname(`%s') failed",
						optarg);
			}
			strncpy(thishostname, optarg, MAXHOSTNAMELEN);
#endif		/* INET6 */
			thishostname[MAXHOSTNAMELEN-1] = '\0';
			break;
		case 'r':
			strncpy(thisdomain, optarg, MAXHOSTNAMELEN);
			thisdomain[MAXHOSTNAMELEN-1] = '\0';
			break;
		case 'l':
			if ((localmode = atoi(optarg)) <= 0)
				errx(1, "Argument to -l is invalid");
			break;
		case 'm':
			strncpy(message503, optarg, MYBUFSIZ);
			message503[MYBUFSIZ-1] = '\0';
			break;
		case 'A':
			strncpy(access_path, optarg, XS_PATH_MAX);
			access_path[XS_PATH_MAX-1] = '\0';
			break;
		case 'R':
			strncpy(refer_path, optarg, XS_PATH_MAX);
			refer_path[XS_PATH_MAX-1] = '\0';
			break;
		case 'E':
			strncpy(error_path, optarg, XS_PATH_MAX);
			error_path[XS_PATH_MAX-1] = '\0';
			break;
		default:
			errx(1, "Usage: httpd [-u username] [-g group] [-p port] [-n number] [-d rootdir]\n[-r refer-ignore-domain] [-l localmode] [-a address] [-m service-message]\n[-A access-log-path] [-E error-log-path] [-R referer-log-path]");
		}
	}
	initsetprocname(argc, argv, envp);
	setup_environment();
        standalone_main();
	exit(0);
}
