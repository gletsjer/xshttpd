/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* $Id: httpd.c,v 1.153 2004/11/26 17:17:27 johans Exp $ */

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
#ifndef		NI_MAXSERV
#define		NI_MAXSERV	32
#define		NI_MAXHOST	1025
#endif		/* NI_MAXSERV */
#ifdef		HAVE_TIME_H
#ifdef		TIME_WITH_SYS_TIME
#include	<time.h>
#endif		/* TIME_WITH_SYS_TIME */
#endif		/* HAVE_TIME_H */
#include	<stdlib.h>
#include	<stdarg.h>
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
#include	"procname.h"
#include	"extra.h"
#include	"cgi.h"
#include	"xscrypt.h"
#include	"path.h"
#include	"convert.h"
#include	"setenv.h"
#include	"local.h"
#include	"mystring.h"
#include	"mygetopt.h"
#include	"htconfig.h"

#ifdef		__linux__
extern	char	*tempnam(const char *, const char *);
#endif		/* __linux__ */

/* This is for HP/UX */
#ifdef		HPUX
extern	int	setpriority (int, int, int);
#endif		/* HPUX */

#ifndef		HAVE_SOCKLEN_T
typedef	size_t	socklen_t;
#endif		/* HAVE_SOCKLEN_T */
#ifndef		PRIO_MAX
#define		PRIO_MAX	20
#endif

#ifndef		lint
static char copyright[] =
"$Id: httpd.c,v 1.153 2004/11/26 17:17:27 johans Exp $ Copyright 1995-2003 Sven Berkvens, Johan van Selst";
#endif

/* Global variables */

int		headers, netbufind, netbufsiz, readlinemode,
		headonly, postonly;
static	int	sd, reqs, mainhttpd = 1;
gid_t		origegid;
uid_t		origeuid;
char		remotehost[NI_MAXHOST],
		currenttime[80], dateformat[MYBUFSIZ], real_path[XS_PATH_MAX],
		version[16], currentdir[XS_PATH_MAX], name[XS_PATH_MAX];
static	char	browser[MYBUFSIZ], referer[MYBUFSIZ], outputbuffer[SENDBUFSIZE],
		thisdomain[NI_MAXHOST], message503[MYBUFSIZ], orig[MYBUFSIZ],
		config_path[XS_PATH_MAX], netbuf[MYBUFSIZ],
		*startparams;
time_t		modtime;
#ifdef		HANDLE_SSL
SSL_CTX			*ssl_ctx;
static SSL		*ssl;
#endif		/* HANDLE_SSL */
struct virtual			*current;
struct configuration	config;

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

static	void	filedescrs		(void);
static	void	detach			(void);
static	void	child_handler		(int);
static	void	term_handler		(int);
static	void	load_config		(void);
static	void	open_logs		(int);
static	void	core_handler		(int);
static	void	set_signals		(void);

static	int	hexdigit		(int);
static	int	decode			(char *);

static	void	uudecode		(char *);
extern	char	*escape			(const char *);

static	void	process_request		(void);

static	void	setup_environment	(void);
static	void	standalone_main		(void);
static	void	standalone_socket	(char);

extern	void
stdheaders(int lastmod, int texthtml, int endline)
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

static	void
filedescrs()
{
	close(0); if (open(BITBUCKETNAME, O_RDONLY, 0) != 0)
		err(1, "Cannot open fd 0 (%s)", BITBUCKETNAME);
	if (dup2(0, 1) != 1)
		err(1, "Cannot dup2() fd 1");
}

static	void
detach()
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
	if (setpgrp(getpid(), 0) == -1)
		err(1, "setpgrp() failed");
#endif		/* HAVE_SETSID */
}

extern	void
setcurrenttime()
{
	time_t		thetime;

	time(&thetime);
	strftime(currenttime, sizeof(currenttime),
		"%a, %d %b %Y %H:%M:%S GMT", gmtime(&thetime));
}

static	void
child_handler(int sig)
{
#ifdef		NeXT
	union	wait	status;
#else		/* Not NeXT */
	int		status;
#endif		/* NeXT */

#ifdef		HAVE_WAIT3
	while (wait3(&status, WNOHANG, NULL) > 0)
		/* NOTHING */;
#endif		/* HAVE_WAIT3 */
	set_signals();
	(void)sig;
}

static	void
term_handler(int sig)
{
	if (mainhttpd)
	{
		setcurrenttime();
		fprintf(stderr, "[%s] Received signal %d, shutting down...\n",
			currenttime, sig);
		fflush(stderr);
		close(sd);
		mainhttpd = 0;
		killpg(0, SIGTERM);
	}
	(void)sig;
	exit(0);
}

static	void
load_config()
{
	int	subtype = 0;
	FILE	*confd;
	char	line[MYBUFSIZ], key[MYBUFSIZ], value[MYBUFSIZ],
			thishostname[NI_MAXHOST];
	char	*comment, *end, *username = NULL, *groupname = NULL;
	struct passwd	*pwd;
	struct group	*grp;
	struct virtual	*last = NULL;
	struct socket_config	*lsock;

	confd = fopen(config_path, "r");

	/* default socket for backwards compatibility */
	lsock = malloc(sizeof(struct socket_config));
	memset(lsock, 0, sizeof(struct socket_config));

	/* Set simple defaults - others follow the parsing */
	config.usecharset = 1;
	config.userestrictaddr = 1;
	config.usevirtualhost = 1;
	config.usecompressed = 1;
	config.script_timeout = 6;
	config.sockets = NULL;
	config.priority = 0;
	config.scriptpriority = PRIO_MAX;
	config.virtualhostdir = NULL;

	if (confd)
	{
		/* skip this loop if there is no config file and use defaults below */
		while (fgets(line, MYBUFSIZ, confd))
		{
			if ((comment = strchr(line, '#')))
				*comment = 0;
			end = line + strlen(line);
			while ((end > line) && (*(end -1 ) <= ' '))
				*(--end) = 0;
			if (end == line)
				continue;
			if ((sscanf(line, "%s \"%[^\"]\"", key, value) == 2) ||
				(sscanf(line, "%s %s", key, value) == 2))
			{
				if (!strcasecmp("SystemRoot", key))
				{
					if (!config.systemroot)
						config.systemroot = strdup(value);
				}
				else if (!strcasecmp("ListenAddress", key))
					lsock->address = strdup(value);
				else if (!strcasecmp("ListenPort", key))
					lsock->port = strdup(value);
				else if (!strcasecmp("ListenFamily", key))
					lsock->family =
						!strcasecmp("IPv4", value) ? PF_INET :
#ifdef		INET6
						!strcasecmp("IPv6", value) ? PF_INET6 :
#endif		/* INET6 */
						PF_UNSPEC;
				else if (!strcasecmp("Instances", key))
				{
					if (!lsock->instances)
						lsock->instances = atoi(value);
				}
				else if (!strcasecmp("PidFile", key))
					config.pidfile = strdup(value);
				else if (!strcasecmp("ExecAsUser", key))
					if (!strcasecmp("true", value))
						config.execasuser = 1;
					else
						config.execasuser = 0;
				else if (!strcasecmp("UseSSL", key))
				{
					if (!strcasecmp("true", value))
#ifdef		HANDLE_SSL
						lsock->usessl = 1;
#else		/* HANDLE_SSL */
						errx(1, "SSL support not enabled at compile-time");
#endif		/* HANDLE_SSL */
				}
				else if (!strcasecmp("SSLCertificate", key))
						config.sslcertificate = strdup(value);
				else if (!strcasecmp("SSLPrivateKey", key))
						config.sslprivatekey = strdup(value);
				else if (!strcasecmp("UseCharset", key))
					config.usecharset = !strcasecmp("true", value);
				else if (!strcasecmp("DefaultCharset", key))
					config.defaultcharset = strdup(value);
				else if (!strcasecmp("UseRestrictAddr", key))
					config.userestrictaddr = !strcasecmp("true", value);
				else if (!strcasecmp("UseVirtualHost", key))
					config.usevirtualhost = !strcasecmp("true", value);
				else if (!strcasecmp("UseVirtualUid", key))
					config.usevirtualuid = !strcasecmp("true", value);
				else if (!strcasecmp("VirtualHostDir", key))
					config.virtualhostdir = strdup(value);
				else if (!strcasecmp("UseLocalScript", key))
					config.uselocalscript = !strcasecmp("true", value);
				else if (!strcasecmp("ScriptTimeout", key))
					config.script_timeout = atoi(value);
				else if (!strcasecmp("UseCompressed", key))
					config.usecompressed = !strcasecmp("true", value);
				else if (!strcasecmp("LocalMode", key))
				{
					if (!config.localmode)
						config.localmode = atoi(value);
					warn("LocalMode is deprecated and will be ignored");
				}
				else if (!current &&
						(!strcasecmp("UserId", key) || 
						 !strcasecmp("GroupId", key)))
					errx(1, "%s directive should be in <System> section", key);
				else if (!strcasecmp("Priority", key))
					config.priority = atoi(value);
				else if (!strcasecmp("ScriptPriority", key))
					config.scriptpriority = atoi(value);
				else if (!current)
					errx(1, "illegal directive: '%s'", key);
				else if (!strcasecmp("Hostname", key))
					current->hostname = strdup(value);
				else if (!strcasecmp("HtmlDir", key))
					current->htmldir = strdup(value);
				else if (!strcasecmp("ExecDir", key))
					current->execdir = strdup(value);
				else if (!strcasecmp("PhExecDir", key))
					current->phexecdir = strdup(value);
				else if (!strcasecmp("VirtualId", key))
					current->virtualid = !strcasecmp("true", value);
				else if (!strcasecmp("LogAccess", key))
					current->logaccess = strdup(value);
				else if (!strcasecmp("LogError", key))
					current->logerror = strdup(value);
				else if (!strcasecmp("LogReferer", key))
					current->logreferer = strdup(value);
				else if (!strcasecmp("LogStyle", key))
					if (!strcasecmp("common", value) ||
							!strcasecmp("traditional", value))
						current->logstyle = traditional;
					else if (!strcasecmp("combined", value) ||
							 !strcasecmp("extended", value))
						current->logstyle = combined;
					else
						errx(1, "illegal logstyle: '%s'", value);
				else if (!strcasecmp("UserId", key))
				{
					if (!current->userid && !(current->userid = atoi(value)))
					{
						if (!(pwd = getpwnam(value)))
							errx(1, "Invalid username: %s", value);
						current->userid = pwd->pw_uid;
					}
				}
				else if (!strcasecmp("GroupId", key))
				{
					if (!current->groupid && !(current->groupid = atoi(value)))
					{
						if (!(grp = getgrnam(value)))
							errx(1, "Invalid groupname: %s", value);
						current->groupid = grp->gr_gid;
					}
				}
				else
					err(1, "illegal directive: '%s'", key);
			}
			else if (sscanf(line, "%s", key) == 1)
			{
				if (!strcasecmp("<System>", key))
				{
					if (subtype)
						err(1, "illegal <System> nesting");
					subtype = 1;
					current = malloc(sizeof(struct virtual));
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Users>", key))
				{
					if (subtype)
						err(1, "illegal <Users> nesting");
					subtype = 2;
					current = malloc(sizeof(struct virtual));
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Virtual>", key))
				{
					if (subtype)
						err(1, "illegal <Virtual> nesting");
					subtype = 3;
					current = malloc(sizeof(struct virtual));
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Socket>", key))
				{
					if (subtype)
						err(1, "illegal <Socket> nesting");
					subtype = 4;
					if (!config.sockets)
					{
						config.sockets = lsock;
					}
					else
					{
						lsock->next = malloc(sizeof(struct socket_config));
						lsock = lsock->next;
						memset(lsock, 0, sizeof(struct socket_config));
					}
				}
				else if (!strcasecmp("</System>", key))
				{
					if (subtype != 1)
						err(1, "</System> end without start");
					if (config.system)
						err(1, "duplicate <System> definition");
					subtype = 0;
					config.system = current;
					current = NULL;
				}
				else if (!strcasecmp("</Users>", key))
				{
					if (subtype != 2)
						err(1, "</Users> end without start");
					if (config.users)
						err(1, "duplicate <Users> definition");
					subtype = 0;
					config.users = current;
					current = NULL;
				}
				else if (!strcasecmp("</Virtual>", key))
				{
					if (subtype != 3)
						err(1, "</Virtual> end without start");
					subtype = 0;
					if (last)
					{
						last->next = current;
						last = last->next;
					}
					else
					{
						config.virtual = current;
						last = config.virtual;
					}
					current = NULL;
				}
				else if (!strcasecmp("</Socket>", key))
				{
					if (subtype != 4)
						err(1, "</Socket> end without start");
					subtype = 0;
				}
				else
					err(1, "illegal directive: '%s'", key);
			}
			else
				err(1, "illegal directive: '%s'", line);
		}
		fclose(confd);
	}
	/* Fill in missing defaults */
	if (!config.systemroot)
		config.systemroot = strdup(HTTPD_ROOT);
	if (!config.sockets)
		config. sockets = lsock;
	for (lsock = config.sockets; lsock; lsock = lsock->next)
	{
		if (!lsock->port)
			lsock->port = lsock->usessl ? strdup("https") : strdup("http");
		if (!lsock->instances)
			lsock->instances = HTTPD_NUMBER;
		config.usessl |= lsock->usessl;
#ifdef		HANDLE_SSL
#endif		/* HANDLE_SSL */
	}
	if (!config.pidfile)
		config.pidfile = strdup(PID_PATH);
	if (!config.localmode)
		config.localmode = 1;
#ifdef		HANDLE_SSL
	if (!config.sslcertificate)
		config.sslcertificate = strdup(CERT_FILE);
	if (!config.sslprivatekey)
		config.sslprivatekey = strdup(KEY_FILE);
#endif		/* HANDLE_SSL */
	/* Set up system section */
	if (!config.system)
	{
		config.system = malloc(sizeof(struct virtual));
		memset(config.system, 0, sizeof(struct virtual));
	}
	if (!config.system->hostname)
	{
		if (gethostname(thishostname, NI_MAXHOST) == -1)
			errx(1, "gethostname() failed");
		config.system->hostname = strdup(thishostname);
	}
	if (!config.system->htmldir)
		config.system->htmldir = strdup(HTTPD_DOCUMENT_ROOT);
	if (!config.system->execdir)
		config.system->execdir = strdup(HTTPD_SCRIPT_ROOT);
	if (!config.system->phexecdir)
		config.system->phexecdir = strdup(HTTPD_SCRIPT_ROOT_P);
	if (!config.system->logaccess)
		config.system->logaccess = strdup(BITBUCKETNAME);
	if (!config.system->logerror)
		config.system->logerror = strdup(BITBUCKETNAME);
	if (!config.system->logreferer)
		config.system->logreferer = strdup(BITBUCKETNAME);
	if (!config.system->logstyle)
		config.system->logstyle = combined;
	if (!username)
		username = strdup(HTTPD_USERID);
	if (!config.system->userid && !(config.system->userid = atoi(username)))
	{
		if (!(pwd = getpwnam(username)))
			errx(1, "Invalid username: %s", username);
		config.system->userid = pwd->pw_uid;
	}
	if (!groupname)
		groupname = strdup(HTTPD_GROUPID);
	if (!config.system->groupid && !(config.system->groupid = atoi(groupname)))
	{
		if (!(grp = getgrnam(groupname)))
			errx(1, "Invalid groupname: %s", groupname);
		config.system->groupid = grp->gr_gid;
	}
	/* Set up users section */
	if (!config.users)
	{
		config.users = malloc(sizeof(struct virtual));
		memset(config.users, 0, sizeof(struct virtual));
	}
	if (!config.users->hostname)
		config.users->hostname = strdup(config.system->hostname);
	if (!config.users->htmldir)
		config.users->htmldir = strdup(HTTPD_USERDOC_ROOT);
	config.system->next = config.users;
	config.users->next = config.virtual;
	/* Check users and virtual sections */
	for (current = config.users; current; current = current->next)
	{
		if (!current->hostname)
			err(1, "illegal virtual block without hostname");
		if (!current->htmldir)
			err(1, "illegal virtual block without directory");
		if (!current->execdir)
			current->execdir = strdup(HTTPD_SCRIPT_ROOT);
		if (!current->phexecdir)
			current->phexecdir = strdup(HTTPD_SCRIPT_ROOT_P);
		if (!current->logstyle)
			current->logstyle = config.system->logstyle;
		if (!current->userid)
			current->userid = config.system->userid;
		if (!current->groupid)
			current->groupid = config.system->groupid;
	}
}

static	void
open_logs(int sig)
{
	FILE		*pidlog;
	char		buffer[XS_PATH_MAX];
	uid_t		savedeuid;
	gid_t		savedegid;
	int		tempfile;

	savedeuid = savedegid = -1;
	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); setegid(origegid);
	}
	if (mainhttpd)
	{
		snprintf(buffer, XS_PATH_MAX, calcpath(config.pidfile));
		buffer[XS_PATH_MAX-1] = '\0';
		(void) remove(buffer);
		if ((pidlog = fopen(buffer, "w")))
		{
			fprintf(pidlog, "%ld\n", (long)getpid());
			fprintf(pidlog, "%s\n", startparams);
			fclose(pidlog);
		}
		else
			warn("cannot open pidfile %s", config.pidfile);
		signal(SIGHUP, SIG_IGN); killpg(0, SIGHUP);
	}

	for (current = config.system; current; current = current->next)
	{
		/* access */
		if (current->logaccess)
		{
			if ('|' != current->logaccess[0])
			{
				if (current->openaccess)
					fclose(current->openaccess);
				if (!(current->openaccess =
					fopen(calcpath(current->logaccess), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logaccess);
				}
			}
			else /* use_pipe */
			{
				if (current->openaccess)
					pclose(current->openaccess);
				if (!(current->openaccess =
					popen(current->logaccess + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logaccess);
				}
			}
#ifndef		SETVBUF_REVERSED
			setvbuf(current->openaccess, NULL, _IOLBF, 0);
#else		/* Not not SETVBUF_REVERSED */
			setvbuf(current->openaccess, _IOLBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */
		}

		/* XXX: evil code duplication */
		if (current->logstyle == traditional && current->logreferer)
		{
			/* referer */
			if ('|' != current->logreferer[0])
			{
				if (current->openreferer)
					fclose(current->openreferer);
				if (!(current->openreferer =
					fopen(calcpath(current->logreferer), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logreferer);
				}
			}
			else /* use pipe */
			{
				if (current->openreferer)
					pclose(current->openreferer);
				if (!(current->openreferer =
					popen(current->logreferer + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logreferer);
				}
			}
#ifndef		SETVBUF_REVERSED
			setvbuf(current->openreferer, NULL, _IOLBF, 0);
#else		/* Not not SETVBUF_REVERSED */
			setvbuf(current->openreferer, _IOLBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */
		}

		/* XXX: evil code duplication */
		if (current->logerror)
		{
			/* error */
			if ('|' != current->logerror[0])
			{
				if (current->openerror)
					fclose(current->openerror);
				if (!(current->openerror =
					fopen(calcpath(current->logerror), "a")))
				{
					err(1, "fopen(`%s' [append])",
						current->logerror);
				}
			}
			else /* use pipe */
			{
				if (current->openerror)
					pclose(current->openerror);
				if (!(current->openerror =
					popen(current->logerror + 1, "w")))
				{
					err(1, "popen(`%s' [write])",
						current->logerror);
				}
			}
#ifndef		SETVBUF_REVERSED
			setvbuf(current->openerror, NULL, _IOLBF, 0);
#else		/* Not not SETVBUF_REVERSED */
			setvbuf(current->openerror, _IOLBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */
		}
	}

	fflush(stderr);
	close(2);
	tempfile = fileno(config.system->openerror);
	if (tempfile != 2)
	{
		if (dup2(tempfile, 2) == -1)
			err(1, "dup2() failed");
	}
	else
		config.system->openerror = stderr;

	if (mainhttpd)
	{
		setcurrenttime();
		fprintf(stderr, "[%s] httpd: Successful restart\n",
			currenttime);
	}
	loadfiletypes(NULL, NULL);
	if (config.usecompressed)
		loadcompresstypes();
	loadscripttypes(NULL, NULL);
#ifdef		HANDLE_SSL
	loadssl();
#endif		/* HANDLE_SSL */
#ifdef		HANDLE_PERL
	loadperl();
#endif		/* HANDLE_PERL */
	set_signals();
	if (!origeuid)
	{
		if (seteuid(savedeuid) == -1)
			err(1, "seteuid()");
		if (setegid(savedegid) == -1)
			err(1, "setegid()");
	}
	(void)sig;
}

extern	void
alarm_handler(int sig)
{
	alarm(0); setcurrenttime();
	fprintf(stderr, "[%s] httpd: Send timed out for `%s'\n",
		currenttime, remotehost[0] ? remotehost : "(none)");
	(void)sig;
	exit(1);
}

static	void
core_handler(int sig)
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

static	void
set_signals()
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

extern	void
error(const char *message)
{
	const	char	*env;

	alarm(180); setcurrenttime();
	env = getenv("QUERY_STRING");
	fprintf((current && current->openerror) ? current->openerror : stderr,
		"[%s] httpd(pid %ld): %s [from: `%s' req: `%s' params: `%s' referer: `%s']\n",
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

extern	void
redirect(const char *redir, int permanent)
{
	const	char	*env;

	env = getenv("QUERY_STRING");
	if (headers)
	{
		if (env)
			secprintf("%s %s moved\r\nLocation: %s?%s\r\n", version,
				permanent ? "301 Permanently" : "302 Temporarily", redir, env);
		else
			secprintf("%s %s moved\r\nLocation: %s\r\n", version,
				permanent ? "301 Permanently" : "302 Temporarily", redir);
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
hexdigit(int ch)
{
	const	char	*temp, *hexdigits = "0123456789ABCDEF";

	if ((temp = strchr(hexdigits, islower(ch) ? toupper(ch) : ch)))
		return (temp - hexdigits);
	else
	{
		error("500 Invalid `percent' parameters");
		return (-1);
	}
}

static	int
decode(char *str)
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
			if ((top = hexdigit((int)poss[1])) < 0)
				return(ERR_QUIT);
			if ((bottom = hexdigit((int)poss[2])) < 0)
				return(ERR_QUIT);
			*(posd++) = (top << 4) + bottom;
			poss += 3;
		}
	}
	*posd = 0;
	return(ERR_NONE);
}

static	void
uudecode(char *buffer)
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
	nprbytes = (bufin - buffer) - 1;
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
check_auth(FILE *authfile)
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
	strncpy(line, env, MYBUFSIZ); line[MYBUFSIZ - 1] = 0;
	find = line + strlen(line);
	while ((find > line) && (*(find - 1) < ' '))
		*(--find) = 0;
	for (search = line; *search && (*search != ' ') && (*search != 9); search++)
		/* DO NOTHING */ ;
	while ((*search == 9) || (*search == ' '))
		search++;
	uudecode(search);
	if ((find = strchr(search, ':')))
	{
		*find++ = 0;
		setenv("REMOTE_USER", search, 1);
		setenv("REMOTE_PASSWORD", find, 1);
		snprintf(line, MYBUFSIZ, "%s:%s\n", search, xs_encrypt(find));
	}
	while (fgets(compare, MYBUFSIZ, authfile))
	{
		if (!strcmp(compare + 1, line))
		{
			fclose(authfile);
			return 0;
		}
	}
	if (headers)
	{
		secprintf("%s 401 Wrong user/password combination\r\n", version);
		secprintf("WWW-authenticate: basic realm=\"this page\"\r\n");
		stdheaders(1, 1, 1);
	}
	secprintf("\r\n<HTML><HEAD><TITLE>Wrong password</TITLE></HEAD>\n");
	secprintf("<BODY><H1>Wrong user/password combination</H1>\n");
	secprintf("You don't have permission to view this page.\n");
	secprintf("</BODY></HTML>\n");
	fclose(authfile);
	return(1);
}

extern	char	*
escape(const char *what)
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

extern	void
server_error(const char *readable, const char *cgi)
{
	struct	stat		statbuf;
	char				cgipath[XS_PATH_MAX],
				*escaped, *temp, filename[] = "/error";
	const	char		*env;
	const	struct	passwd	*userinfo;

	if (!current)
		current = config.system;
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
	/* Look for user-defined error script */
	if (current == config.users &&
		(userinfo = getpwuid(geteuid())) &&
		userinfo->pw_uid)
	{
		char	base[XS_PATH_MAX];
		(void) transform_user_dir(base, userinfo, 1);
		snprintf(cgipath, XS_PATH_MAX, "%s%s%s",
			base, current->phexecdir, filename);
	}
	else	/* Look for virtual host error script */
	{
		snprintf(cgipath, XS_PATH_MAX, "%s%s",
			calcpath(current->phexecdir), filename);
	}
	if (stat(cgipath, &statbuf))
	{
		/* Last resort: try system error script */
		snprintf(cgipath, XS_PATH_MAX, "%s%s",
			calcpath(config.system->phexecdir), filename);
		if (stat(cgipath, &statbuf))
		{
			error(readable);
			return;
		}
	}
	if ((temp = strrchr(cgipath, '/')))
		*temp = '\0';
	setcurrenttime();
	fprintf((current && current->openerror) ? current->openerror : stderr,
		"[%s] httpd(pid %ld): %s [from: `%s' req: `%s' params: `%s' referer: `%s']\n",
		currenttime, (long)getpid(), readable,
		remotehost[0] ? remotehost : "(none)",
		orig[0] ? orig : "(none)", env ? env : "(none)",
		referer[0] ? referer : "(none)");
	do_script(orig, cgipath, filename, NULL, 1);
}

extern	void
logrequest(const char *request, long size)
{
	char		buffer[80], *dynrequest, *dynagent, *p;
	time_t		theclock;
	FILE		*alog;

	time(&theclock);
	strftime(buffer, 80, "%d/%b/%Y:%H:%M:%S", localtime(&theclock));

	if (!current->openaccess)
		if (!config.system->openaccess)
		{
			fprintf(stderr, "Logfile disappeared???\n");
			return;
		}
		else
			alog = config.system->openaccess;
	else
		alog = current->openaccess;

	dynrequest = dynagent = NULL;
	if (request && (dynrequest = strdup(request)))
		for (p = dynrequest; *p; p++)
			if ('\"' == *p)
				*p = '\'';
	if (getenv("USER_AGENT") && (dynagent = strdup(getenv("USER_AGENT"))))
		for (p = dynagent; *p; p++)
			if ('\"' == *p)
				*p = '\'';
	if (current->logstyle == traditional)
	{
		FILE	*rlog = current->openreferer
			? current->openreferer
			: config.system->openreferer;
		fprintf(alog, "%s - - [%s +0000] \"%s %s %s\" 200 %ld\n",
			remotehost,
			buffer, 
			getenv("REQUEST_METHOD"), dynrequest, version,
			size > 0 ? (long)size : (long)0);
		if (rlog &&
			(!thisdomain[0] || !strcasestr(referer, thisdomain)))
			fprintf(rlog, "%s -> %s\n", referer, request);
	}
	else
		fprintf(alog, "%s - - [%s +0000] \"%s %s %s\" 200 %ld "
				"\"%s\" \"%s\"\n",
			remotehost,
			buffer, 
			getenv("REQUEST_METHOD"), dynrequest, version,
			size > 0 ? (long)size : (long)0,
			referer,
			dynagent);

	free(dynrequest);
	free(dynagent);
}

int
secread(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (config.usessl && fd == 0)
		return SSL_read(ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return read(fd, buf, count);
}

int
secwrite(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return write(fd, buf, count);
}

int
secfwrite(void *buf, size_t size, size_t count, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, size), count;
	else
#endif		/* HANDLE_SSL */
		return fwrite(buf, size, count, stream);
}

int
secprintf(const char *format, ...)
{
	va_list	ap;
	char	buf[4096];

	va_start(ap, format);
	vsnprintf(buf, 4096, format, ap);
	va_end(ap);
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return printf("%s", buf);
}

int
secfputs(char *buf, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return fputs(buf, stream);
}

extern	int
readline(int rd, char *buf)
{
	char		ch, *buf2;

	buf2 = buf; *buf2 = 0;
	do
	{
		if (netbufind >= netbufsiz)
		{
			TRYAGAIN:
			netbufsiz = secread(rd, netbuf,
				readlinemode ? MYBUFSIZ : 1);
			if (netbufsiz == -1)
			{
				if ((errno == EAGAIN) || (errno == EINTR))
				{
					mysleep(1); goto TRYAGAIN;
				}
				fprintf(stderr, "[%s] httpd: readline(): %s [%d]\n",
					currenttime, strerror(errno), rd);
				if (rd == 0)
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
				if (rd == 0)
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

static	void
process_request()
{
	char		line[MYBUFSIZ], extra[MYBUFSIZ], *temp, ch,
			*params, *url, *ver, http_host[NI_MAXHOST];
	int		readerror;
	size_t		size;

	strcpy(version, "HTTP/0.9");
	strcpy(dateformat, "%a %b %e %H:%M:%S %Y");
	orig[0] = referer[0] = line[0] =
		real_path[0] = browser[0] = 0;
	netbufsiz = netbufind = headonly = postonly = headers = 0;
	unsetenv("SERVER_NAME");
	unsetenv("CONTENT_LENGTH"); unsetenv("AUTH_TYPE");
	unsetenv("CONTENT_TYPE"); unsetenv("QUERY_STRING");
	unsetenv("PATH_INFO"); unsetenv("PATH_TRANSLATED");
	unsetenv("ORIG_PATH_INFO"); unsetenv("ORIG_PATH_TRANSLATED");
	unsetenv("SCRIPT_FILENAME");
	unsetenv("ERROR_CODE"); unsetenv("ERROR_READABLE");
	unsetenv("ERROR_URL"); unsetenv("ERROR_URL_ESCAPED");
	unsetenv("ERROR_URL_EXPANDED"); unsetenv("REMOTE_USER");
	unsetenv("REMOTE_PASSWORD");
	unsetenv("HTTP_REFERER"); unsetenv("HTTP_COOKIE");
	unsetenv("HTTP_ACCEPT"); unsetenv("HTTP_ACCEPT_ENCODING");
	unsetenv("HTTP_ACCEPT_LANGUAGE"); unsetenv("HTTP_HOST");
	unsetenv("HTTP_NEGOTIONATE"); unsetenv("HTTP_PRAGMA");
	unsetenv("HTTP_CLIENT_IP"); unsetenv("HTTP_VIA");
	unsetenv("HTTP_AUTHORIZATION");
	unsetenv("IF_MODIFIED_SINCE"); unsetenv("IF_UNMODIFIED_SINCE");
	unsetenv("IF_RANGE");
	unsetenv("SSL_CIPHER");

	http_host[0] = '\0';

	alarm(180); errno = 0;
#ifdef		HANDLE_SSL
	if (config.usessl)
		setenv("SSL_CIPHER", SSL_get_cipher(ssl), 1);
	if ((readerror = ERR_get_error())) {
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
	readlinemode = strncasecmp("POST", line, 4) ? READBLOCK : READCHAR;
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
				(void) strtok(browser, "/");
				for (temp = browser; *temp; temp++)
					if (isupper(*temp))
						*temp = tolower(*temp);
				if (islower(*browser))
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
			{
				setenv("AUTH_TYPE", param, 1);
				setenv("HTTP_AUTHORIZATION", param, 1);
			} else if (!strcasecmp("Cookie", extra))
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
	} else if (!strncasecmp(ver, "HTCPCP/", 7))
	{
		headers = 1;
		strcpy(version, "HTCPCP/1.0");
		error("418 Duh... I'm a webserver Jim, not a coffeepot!");
		return;
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
	bzero(orig, size + 16);
	bcopy(params, orig, size);

	if (size < NI_MAXHOST &&
		sscanf(params, "http://%[^/]%c", http_host, &ch) == 2 &&
		ch == '/')
	{
		/* absoluteURI's are supported by HTTP/1.1,
		 * this syntax is preferred over Host-headers(!)
		 */
		setenv("HTTP_HOST", http_host, 1);
		params += strlen(http_host) + 7;
		bcopy(params, orig, strlen(params));
	}
	else if (params[0] != '/' && strcmp("OPTIONS", line))
	{
		server_error("400 Relative URL's are not supported",
			"NO_RELATIVE_URLS");
		return;
	}
	/* SERVER_NAME may be overriden soon */
	setenv("SERVER_NAME", config.system->hostname, 1);
	if ((temp = getenv("HTTP_HOST")))
	{
		temp = strncpy(http_host, temp, NI_MAXHOST);
		temp[NI_MAXHOST-1] = '\0';
		for ( ; *temp; temp++)
			if ((*temp < 'a' || *temp > 'z') &&
				(*temp < 'A' || *temp > 'Z') &&
				(*temp < '0' || *temp > '9') &&
				*temp != '-' && *temp != '.' &&
				*temp != ':' &&
				*temp != '[' && *temp != ']')
			{
				server_error("400 Invalid Host Header", "BAD_REQUEST");
				return;
			}
		if ((temp = strchr(http_host, ':')))
			*temp = '\0';
		temp = http_host + strlen(http_host);
		while (temp > http_host && *(--temp) == '.')
			*temp = '\0';
		if (strcmp(config.port, config.usessl ? "https" : "http") &&
			strcmp(config.port, config.usessl ? "443" : "80"))
		{
			if (strlen(http_host) >= NI_MAXHOST - 6)
			{
				server_error("400 Invalid Host Header", "BAD_REQUEST");
				return;
			}
			strcat(http_host, ":");
			strcat(http_host, config.port);
		}
		unsetenv("HTTP_HOST");
		/* Ignore unqualified names - it could be a subdirectory! */
		if ((strlen(http_host) > 3) && strchr(http_host, '.'))
		{
			setenv("HTTP_HOST", http_host, 1);
			unsetenv("SERVER_NAME");
			setenv("SERVER_NAME", http_host, 1);
		}
	}
	else if (headers >= 11)
	{
		server_error("400 Missing Host Header", "BAD_REQUEST");
		return;
	}

	if ((temp = strchr(http_host, ':')))
		*temp = '\0';
	for (current = config.virtual; current; current = current->next)
		if (!strcasecmp(http_host, current->hostname))
			break;
	if (params[0] && params[1] == '~')
		current = config.users;
	else if (!current)
		current = config.system;

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

static	void
standalone_main()
{
	struct	socket_config	*sock;
	pid_t					pid;
	char					id = 'A';

	detach(); open_logs(0);

	for (sock = config.sockets; sock; sock = sock->next)
	{
		config.family	= sock->family;
		config.address	= sock->address;
		config.port	= sock->port;
		config.instances= sock->instances;
		config.usessl	= sock->usessl;

		if (sock->next)
			/* spawn auxiliary master */
			switch ((pid = fork()))
			{
			case -1:
				warn("fork() failed");
				killpg(0, SIGTERM);
				exit(1);
			case 0:
				mainhttpd = 0;
				standalone_socket(id);
				exit(0);
			default:
				id++;
			}
		else
			/* make myself useful */
			standalone_socket(id);
	}
}

static	void
standalone_socket(char id)
{
	int			csd = 0, count, temp;
	socklen_t		clen;
#ifdef		HAVE_GETADDRINFO
	struct	addrinfo	hints, *res;
	struct	sockaddr_storage	saddr;
#else		/* HAVE_GETADDRINFO */
	struct	sockaddr	saddr;
	unsigned	short	sport;
#endif		/* HAVE_GETADDRINFO */
#ifndef		HAVE_GETNAMEINFO
	unsigned	long	laddr;
#endif		/* HAVE_GETNAMEINFO */
	pid_t			*childs, pid;
#ifdef		HAVE_SETRLIMIT
	struct	rlimit		limit;
#endif		/* HAVE_SETRLIMIT */

	setprocname("xs(MAIN): Initializing deamons...");

#ifdef		HAVE_GETADDRINFO
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = config.family;
#ifdef		__linux__
	if (config.family == PF_UNSPEC)
#ifdef		INET6
		hints.ai_family = PF_INET6;
#else		/* INET6 */
		hints.ai_family = PF_INET;
#endif		/* INET6 */
#endif		/* __linux__ */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((getaddrinfo(config.address ? config.address : NULL, config.port,
			&hints, &res)))
		err(1, "getaddrinfo()");

	/* only look at the first address */
	if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
		err(1, "socket()");
#else		/* HAVE_GETADDRINFO */
	if ((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");
#endif		/* HAVE_GETADDRINFO */

#ifdef	SO_REUSEPORT
	temp = 1;
	if ((setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &temp, sizeof(temp))) == -1)
		err(1, "setsockopt(REUSEPORT)");
#else	/* HAVE_SO_REUSEPORT */
#ifdef	SO_REUSEADDR
	temp = 1;
	if ((setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &temp, sizeof(temp))) == -1)
		err(1, "setsockopt(REUSEADDR)");
#endif	/* SO_REUSEADDR */
#endif	/* SO_REUSEPORT */

	temp = 1;
	if ((setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &temp, sizeof(temp))) == -1)
		err(1, "setsockopt(KEEPALIVE)");

#ifdef		HAVE_GETADDRINFO
	if (bind(sd, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "bind()");

	freeaddrinfo(res);
#else		/* HAVE_GETADDRINFO */
	/* Quick patch to run on old systems */
	memset(&saddr, 0, sizeof(struct sockaddr));
	saddr.sa_family = PF_INET;
	if (!strcmp(config.port, "http"))
		sport = 80;
	else if (!strcmp(config.port, "https"))
		sport = 443;
	else
		sport = atoi(config.port) || 80;
	((struct sockaddr_in *)&saddr)->sin_port = htons(sport);

	if (bind(sd, &saddr, sizeof(struct sockaddr)) == -1)
		err(1, "bind()");
#endif		/* HAVE_GETADDRINFO */

	if (listen(sd, MAXLISTEN))
		err(1, "listen()");

#ifdef		HAVE_SETRLIMIT
#ifdef		RLIMIT_NPROC
	limit.rlim_max = limit.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_NPROC, &limit);
#endif		/* RLIMIT_NPROC */
#ifdef		RLIMIT_CPU
	limit.rlim_max = limit.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_CPU, &limit);
#endif		/* RLIMIT_CPU */
#endif		/* HAVE_SETRLIMIT */

	set_signals(); reqs = 0;
	if (!(childs = (pid_t *)malloc(sizeof(pid_t) * config.instances)))
		errx(1, "malloc() failed");

	for (count = 0; count < config.instances; count++)
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
		setprocname("xs(MAIN-%c): Waiting for dead children", id);
		while (mysleep(30))
			/* NOTHING HERE */;
		setprocname("xs(MAIN-%c): Searching for dead children", id);
		for (count = 0; count < config.instances; count++)
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
		if (count > config.instances || count < 0)
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

		setprocname("xs(%c%d): [Reqs: %06d] Setting up myself to accept a connection",
			id, count + 1, reqs);
		if (!origeuid && (seteuid(origeuid) == -1))
			err(1, "seteuid(%ld) failed", (long)origeuid);
		if (!origeuid && (setegid(origegid) == -1))
			err(1, "setegid(%ld) failed", (long)origegid);
		filedescrs();
		setprocname("xs(%c%d): [Reqs: %06d] Waiting for a connection...",
			id, count + 1, reqs);
		clen = sizeof(saddr);
		if ((csd = accept(sd, (struct sockaddr *)&saddr, &clen)) < 0)
		{
			if (errno == EINTR)
				child_handler(SIGCHLD);
			continue;
		}
		setprocname("xs(%c%d): [Reqs: %06d] accept() gave me a connection...",
			id, count + 1, reqs);
		if (fcntl(csd, F_SETFL, 0))
			warn("fcntl() in standalone_main");

		sl.l_onoff = 1; sl.l_linger = 600;
		setsockopt(csd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#if 0
#ifdef		SO_SNDBUF
		temp = SENDBUFSIZE + 64;
		setsockopt(csd, SOL_SOCKET, SO_SNDBUF, &temp, sizeof(temp));
#endif		/* SO_SNDBUF */
#ifdef		SO_RCVBUF
		temp = 512;
		setsockopt(csd, SOL_SOCKET, SO_RCVBUF, &temp, sizeof(temp));
#endif		/* SO_RCVBUF */
#endif		/* 0 */

		dup2(csd, 0); dup2(csd, 1);
		if (!config.usessl)
			close(csd);

#ifndef		SETVBUF_REVERSED
		setvbuf(stdin, NULL, _IONBF, 0);
#else		/* Not not SETVBUF_REVERSED */
		setvbuf(stdin, _IONBF, NULL, 0);
#endif		/* SETVBUF_REVERSED */

#ifdef		HAVE_GETNAMEINFO
		if (!getnameinfo((struct sockaddr *)&saddr, clen,
			remotehost, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
		{
			remotehost[NI_MAXHOST-1] = '\0';
			/* Fake $REMOTE_ADDR because most people don't
			 * (want to) understand ::ffff: adresses.
			 */
			if (strncmp(remotehost, "::ffff:", 7))
				setenv("REMOTE_ADDR", remotehost, 1);
			else
				setenv("REMOTE_ADDR", remotehost + 7, 1);
		}
#else		/* HAVE_GETNAMEINFO */
		/* I don't need libnsl for this... */
		laddr = ntohl(((struct sockaddr_in *)&saddr)->sin_addr.s_addr);
		sprintf(remotehost, "%d.%d.%d.%d",
			(laddr & 0xff000000) >> 24,
			(laddr & 0x00ff0000) >> 16,
			(laddr & 0x0000ff00) >> 8,
			(laddr & 0x000000ff));
		setenv("REMOTE_HOST", remotehost, 1);
#endif		/* HAVE_GETNAMEINFO */

#ifdef		HAVE_GETNAMEINFO
#ifndef		BROKEN_GETNAMEINFO
		if (!getnameinfo((struct sockaddr *)&saddr, clen,
			remotehost, sizeof(remotehost), NULL, 0, 0))
		{
			remotehost[NI_MAXHOST-1] = '\0';
			setenv("REMOTE_HOST", remotehost, 1);
		}
#endif		/* Not BROKEN_GETNAMEINFO */
#else		/* HAVE GETNAMEINFO */
#ifdef		HAVE_GETADDRINFO
		/* This is especially for broken Linux distro's
		 * that don't understand what getnameinfo() does
		 * Let's abuse getaddrinfo() instead...
		 */
		hints.ai_family = PF_INET;
		hints.ai_flags = AI_CANONNAME;
		if (!getaddrinfo(
			(strncmp(remotehost, "::ffff:", 7) ? remotehost : remotehost + 7),
			NULL, &hints, &res))
		{
			setenv("REMOTE_HOST", res->ai_canonname, 1);
			freeaddrinfo(res);
		}
#else		/* HAVE_GETADDRINFO */
		/* Loooser! You will just have to use the IP-adres... */
#endif		/* HAVE_GETADDRINFO */
#endif		/* HAVE GETNAMEINFO */
#ifdef		HANDLE_SSL
		if (config.usessl) {
			ssl = SSL_new(ssl_ctx);
			SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
			SSL_set_fd(ssl, csd);
			if (!SSL_accept(ssl)) {
				fprintf(stderr, "SSL flipped\n");
				secprintf("%s 500 Failed\r\nContent-type: text/plain\r\n\r\n",
					version);
				secprintf("SSL Flipped...\n");
				free(childs);
				return;
			}
		}
#endif		/* HANDLE_SSL */
		setprocname("xs(%d): Connect from `%s'", count + 1, remotehost);
		setcurrenttime();
		if (message503[0])
		{
			alarm(180);
			secprintf("HTTP/1.0 503 Busy\r\nContent-type: text/plain\r\n\r\n");
			secprintf("%s\r\n", message503);
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

static	void
setup_environment()
{
	char		buffer[16];

	setenv("SERVER_SOFTWARE", SERVER_IDENT, 1);
	setenv("SERVER_NAME", config.system->hostname, 1);
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	setenv("SERVER_PORT", "80", 1);
	setenv("SERVER_PORT",
		!config.port ? "80" :
		!strcmp(config.port, "http") ? "80" :
		!strcmp(config.port, "https") ? "443" :
		config.port,
		1);
	snprintf(buffer, 16, "%d", config.localmode);
	buffer[15] = '\0';
	setenv("LOCALMODE", buffer, 1);
	setenv("HTTPD_ROOT", config.systemroot, 1);
}

int
main(int argc, char **argv, char **envp)
{
	int			option, num;
	int			nolog = 0;
	enum { optionp, optiond, optionhd, optionhn, optionaa, optionrr, optionee };
	char *		longopt[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, };
	uid_t		uid = 0;
	gid_t		gid = 0;
	const struct passwd	*userinfo;
	const struct group	*groupinfo;

	origeuid = geteuid(); origegid = getegid();
	memset(&config, 0, sizeof config);

#ifdef		HAVE_SETPRIORITY
	if (setpriority(PRIO_PROCESS, (pid_t)0, config.priority))
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

	message503[0] = 0;
#ifdef		THISDOMAIN
	strncpy(thisdomain, THISDOMAIN, NI_MAXHOST);
	thisdomain[NI_MAXHOST-1] = '\0';
#else		/* Not THISDOMAIN */
	thisdomain[0] = 0;
#endif		/* THISDOMAIN */
	snprintf(config_path, XS_PATH_MAX, "%s/httpd.conf", calcpath(HTTPD_ROOT));
	config_path[XS_PATH_MAX-1] = '\0';
	while ((option = getopt(argc, argv, "a:c:d:g:l:m:n:p:r:su:vA:D:E:R:N")) != EOF)
	{
		switch(option)
		{
		case 'n':
			if ((config.instances = atoi(optarg)) <= 0)
				errx(1, "Invalid number of processes");
			break;
		case 'p':
			longopt[optionp] = optarg;
			break;
		case 'a':
			longopt[optionhn] = optarg;
			break;
		case 's':
#ifdef		HANDLE_SSL
			config.usessl = 1;
#else		/* HANDLE_SSL */
			errx(1, "SSL support not enabled at compile-time");
#endif		/* HANDLE_SSL */
			break;
		case 'u':
			if ((uid = atoi(optarg)) > 0)
				break;
			if (!(userinfo = getpwnam(optarg)))
				errx(1, "Invalid user ID");
			uid = userinfo->pw_uid;
			break;
		case 'g':
			if ((gid = atoi(optarg)) > 0)
				break;
			if (!(groupinfo = getgrnam(optarg)))
				errx(1, "Invalid group ID");
			gid = groupinfo->gr_gid;
			break;
		case 'd':
			if (*optarg != '/')
				errx(1, "The -d directory must start with a /");
			longopt[optiond] = optarg;
			break;
		case 'D':
			longopt[optionhd] = optarg;
			break;
		case 'r':
			strncpy(thisdomain, optarg, NI_MAXHOST);
			thisdomain[NI_MAXHOST-1] = '\0';
			break;
		case 'l':
			errx(1, "-l is deprecated: use Users/HtmlDir");
			break;
		case 'm':
			strncpy(message503, optarg, MYBUFSIZ);
			message503[MYBUFSIZ-1] = '\0';
			break;
		case 'c':
			strncpy(config_path, optarg, XS_PATH_MAX);
			config_path[XS_PATH_MAX-1] = '\0';
			break;
	 	case 'A':
			longopt[optionaa] = optarg;
			break;
	 	case 'R':
			longopt[optionrr] = optarg;
			break;
	 	case 'E':
			longopt[optionee] = optarg;
			break;
		case 'N':
			nolog = 1;
			strcpy(config_path, "/dev/null");
			break;
		case 'v':
			fprintf(stdout, "%s\n", SERVER_IDENT);
			return 0;
		default:
			errx(1, "Usage: httpd [-u username] [-g group] [-p port] [-n number]\n[-d rootdir] [-D documentdir] [-r refer-ignore-domain] [-l localmode]\n[-A access_log] [-E error_log] [-R referrer_log] [-m service-message] [-s]");
		}
	}
	load_config();

	/* Explicity set these, overriding default or implicit setting */
#define	SET_OPTION(option, config) \
	if (longopt[option]) { \
		if (config) \
			free(config); \
		config = strdup(longopt[option]); \
	}

	if (nolog)
	{
			config.pidfile =
					config.system->logaccess =
					config.system->logreferer =
					config.system->logerror =
					strdup("/dev/null");
	}
	if (config.sockets)
			SET_OPTION(optionp,  config.sockets[0].port);
	SET_OPTION(optiond,  config.systemroot);
	SET_OPTION(optionhd, config.system->htmldir);
	SET_OPTION(optionhn, config.system->hostname);
	SET_OPTION(optionaa, config.system->logaccess);
	SET_OPTION(optionrr, config.system->logreferer);
	SET_OPTION(optionee, config.system->logerror);
	if (uid)
		config.system->userid = uid;
	if (gid)
		config.system->groupid = gid;

	initsetprocname(argc, argv, envp);
	setup_environment();
	standalone_main();
	(void)copyright;
	return 0;
}
