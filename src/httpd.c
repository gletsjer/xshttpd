/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* $Id: httpd.c,v 1.207 2005/11/06 10:34:07 johans Exp $ */

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
#include	<sys/utsname.h>
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
#ifdef		AUTH_LDAP
#include	"ldap.h"
#endif		/* AUTH_LDAP */
#ifndef		HAVE_SETPROCTITLE
#include	"setproctitle.h"
#endif		/* HAVE_SETPROCTITLE */

#include	"httpd.h"
#include	"decode.h"
#include	"methods.h"
#include	"extra.h"
#include	"cgi.h"
#include	"ssl.h"
#include	"xscrypt.h"
#include	"path.h"
#include	"convert.h"
#include	"setenv.h"
#include	"local.h"
#include	"mystring.h"
#include	"htconfig.h"

#ifndef		HAVE_SOCKLEN_T
typedef	size_t	socklen_t;
#endif		/* HAVE_SOCKLEN_T */
#ifndef		HAVE_DECL_ENVIRON
extern	char	**environ;
#endif		/* HAVE_DECL_ENVIRON */
#ifndef		PRIO_MAX
#define		PRIO_MAX	20
#endif

#define		MAXVHOSTALIASES		32

static char copyright[] =
"$Id: httpd.c,v 1.207 2005/11/06 10:34:07 johans Exp $ Copyright 1995-2005 Sven Berkvens, Johan van Selst";

/* Global variables */

int		headers, headonly, postonly;
static	int	sd, reqs, mainhttpd = 1;
gid_t		origegid;
uid_t		origeuid;
char		remotehost[NI_MAXHOST],
		currenttime[80], dateformat[MYBUFSIZ], real_path[XS_PATH_MAX],
		version[16], currentdir[XS_PATH_MAX],
		orig_filename[XS_PATH_MAX];
static	char	browser[MYBUFSIZ], referer[MYBUFSIZ], outputbuffer[SENDBUFSIZE],
		thisdomain[NI_MAXHOST], message503[MYBUFSIZ], orig[MYBUFSIZ],
		config_path[XS_PATH_MAX], authentication[MYBUFSIZ],
		*startparams;
time_t		modtime;
struct virtual			*current;
struct configuration	config;

/* Prototypes */

static	void	filedescrs		(void);
static	void	detach			(void);
static	void	child_handler		(int);
static	void	term_handler		(int);
static	void	load_config		(void);
static	void	open_logs		(int);
static	void	core_handler		(int);
static	void	set_signals		(void);

static	void	process_request		(void);

static	void	setup_environment	(void);
static	void	standalone_main		(void);
static	void	standalone_socket	(int);

void
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

void
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
	(void)status;
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
	char	line[MYBUFSIZ], thishostname[NI_MAXHOST];
	char	*key, *value;
	char	*comment, *end, *username = NULL, *groupname = NULL;
	char	**defaultindexfiles;
	struct passwd	*pwd;
	struct group	*grp;
	struct virtual	*last = NULL;
	struct socket_config	*lsock;

	confd = fopen(config_path, "r");

	/* default socket for backwards compatibility */
	lsock = malloc(sizeof(struct socket_config));
	if (!lsock)
		err(1, "Fatal error");
	memset(lsock, 0, sizeof(struct socket_config));
	if (config.instances)
		lsock->instances = config.instances;

	/* Set simple defaults - others follow the parsing */
	config.usecharset = 1;
	config.userestrictaddr = 1;
	config.usevirtualhost = 1;
	config.usecompressed = 1;
	config.usednslookup = 1;
	config.script_cpu_limit = 2;
	config.script_timeout = 6;
	config.sockets = NULL;
	config.priority = 0;
	config.scriptpriority = PRIO_MAX;
	config.virtualhostdir = NULL;

	defaultindexfiles = malloc(MAXINDEXFILES);
	defaultindexfiles[0] = strdup("index.html");
	defaultindexfiles[1] = strdup("index.htm");
	defaultindexfiles[2] = strdup("index.php");
	defaultindexfiles[3] = NULL;

	if (confd)
	{
		/* skip this loop if there is no config file and use defaults below */
		while (fgets(line, MYBUFSIZ, confd))
		{
			if ((comment = strchr(line, '#')))
				*comment = 0;
			end = line + strlen(line);
			while ((end > line) && (*(end - 1) <= ' '))
				*(--end) = 0;
			if (end == line)
				continue;
			key = line;

			if ((value = strpbrk(line, "\t ")))
			{
				*value++ = 0;
				while ('\t' == *value || ' ' == *value)
					value++;

				/* quotes are optional - for historical reasons */
				if (('"' == value[0]) && (end = strchr(value + 1, '"')))
				{
					value++;
					*end = '\0';
				}
			}

			if (value && strlen(value))
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
					if (!strcasecmp("true", value))
						lsock->usessl = 1;
					else
						lsock->usessl = 0;
				else if (!strcasecmp("SSLCertificate", key))
				{
					lsock->usessl = 1;
					config.sslcertificate =
						lsock->sslcertificate =
							strdup(value);
				}
				else if (!strcasecmp("SSLPrivateKey", key))
				{
					lsock->usessl = 1;
					config.sslprivatekey =
						lsock->sslprivatekey =
							strdup(value);
				}
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
				else if (!strcasecmp("UseDnsLookup", key))
					config.usednslookup = !strcasecmp("true", value);
				else if (!strcasecmp("VirtualHostDir", key))
					config.virtualhostdir = strdup(value);
				else if (!strcasecmp("UseLocalScript", key))
					config.uselocalscript = !strcasecmp("true", value);
				else if (!strcasecmp("UsePcreRedir", key))
					config.usepcreredir = !strcasecmp("true", value);
				else if (!strcasecmp("UseLdapAuth", key))
					config.useldapauth = !strcasecmp("true", value);
				else if (!strcasecmp("ScriptCpuLimit", key))
					config.script_cpu_limit = atoi(value);
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
				else if (!strcasecmp("HostAlias", key))
				{
					int		i;
					char	*prev = NULL, *next = value;

					current->aliases = malloc(MAXVHOSTALIASES);
					for (i = 0; i < MAXVHOSTALIASES; )
					{
						if ((prev = strsep(&next, ", \t")) && *prev)
							current->aliases[i++] = strdup(prev);
						else if (!prev)
						{
							current->aliases[i] = NULL;
							break;
						}
					}
				}
				else if (!strcasecmp("HtmlDir", key))
					current->htmldir = strdup(value);
				else if (!strcasecmp("ExecDir", key))
					current->execdir = strdup(value);
				else if (!strcasecmp("PhExecDir", key))
					current->phexecdir = strdup(value);
				else if (!strcasecmp("LogAccess", key))
					current->logaccess = strdup(value);
				else if (!strcasecmp("LogError", key))
					current->logerror = strdup(value);
				else if (!strcasecmp("LogReferer", key))
					current->logreferer = strdup(value);
				else if (!strcasecmp("IndexFiles", key))
				{
					int		i;
					char	*prev = NULL, *next = value;

					current->indexfiles = malloc(MAXINDEXFILES);
					for (i = 0; i < MAXINDEXFILES; )
					{
						if ((prev = strsep(&next, ", \t")) && *prev)
							current->indexfiles[i++] = strdup(prev);
						else if (!prev)
						{
							current->indexfiles[i] = NULL;
							break;
						}
					}
				}
				else if (!strcasecmp("LogStyle", key))
					if (!strcasecmp("common", value) ||
							!strcasecmp("traditional", value))
						current->logstyle = traditional;
					else if (!strcasecmp("combined", value) ||
							 !strcasecmp("extended", value))
						current->logstyle = combined;
					else if (!strcasecmp("virtual", value))
						current->logstyle = virtual;
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
					errx(1, "illegal directive: '%s'", key);
			}
			else if (strlen(key))
			{
				if (!strcasecmp("<System>", key))
				{
					if (subtype)
						errx(1, "illegal <System> nesting");
					subtype = 1;
					current = malloc(sizeof(struct virtual));
					if (!current)
						err(1, "Fatal error");
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Users>", key))
				{
					if (subtype)
						errx(1, "illegal <Users> nesting");
					subtype = 2;
					current = malloc(sizeof(struct virtual));
					if (!current)
						err(1, "Fatal error");
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Virtual>", key))
				{
					if (subtype)
						errx(1, "illegal <Virtual> nesting");
					subtype = 3;
					current = malloc(sizeof(struct virtual));
					if (!current)
						err(1, "Fatal error");
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Socket>", key))
				{
					if (subtype)
						errx(1, "illegal <Socket> nesting");
					subtype = 4;
					if (!config.sockets)
					{
						config.sockets = lsock;
					}
					else
					{
						lsock->next = malloc(sizeof(struct socket_config));
						if (!lsock->next)
							err(1, "Fatal error");
						lsock = lsock->next;
						memset(lsock, 0, sizeof(struct socket_config));
					}
				}
				else if (!strcasecmp("</System>", key))
				{
					if (subtype != 1)
						errx(1, "</System> end without start");
					if (config.system)
						errx(1, "duplicate <System> definition");
					subtype = 0;
					config.system = current;
					current = NULL;
				}
				else if (!strcasecmp("</Users>", key))
				{
					if (subtype != 2)
						errx(1, "</Users> end without start");
					if (config.users)
						errx(1, "duplicate <Users> definition");
					subtype = 0;
					config.users = current;
					current = NULL;
				}
				else if (!strcasecmp("</Virtual>", key))
				{
					if (subtype != 3)
						errx(1, "</Virtual> end without start");
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
						errx(1, "</Socket> end without start");
					subtype = 0;
				}
				else
					errx(1, "illegal directive: '%s'", key);
			}
			else
				errx(1, "illegal directive: '%s'", line);
		}
		fclose(confd);
	}
	/* Fill in missing defaults */
	if (!config.systemroot)
		config.systemroot = strdup(HTTPD_ROOT);
	if (!config.sockets)
		config.sockets = lsock;
	for (lsock = config.sockets; lsock; lsock = lsock->next)
	{
		if (!lsock->port)
			lsock->port = lsock->usessl ? strdup("https") : strdup("http");
		if (!lsock->instances)
			lsock->instances = HTTPD_NUMBER;
		if (lsock->usessl)
		{
#ifdef		HANDLE_SSL
			if (!lsock->sslcertificate)
				lsock->sslcertificate = config.sslcertificate;
			if (!lsock->sslprivatekey)
				lsock->sslprivatekey = config.sslprivatekey;
#else		/* HANDLE_SSL */
			/* Sanity check */
			errx(1, "SSL support configured but not compiled in");
#endif		/* HANDLE_SSL */
		}
	}
	if (!config.pidfile)
		config.pidfile = strdup(PID_PATH);
	if (!config.localmode)
		config.localmode = 1;
	/* Sanity check */
#ifndef		AUTH_LDAP
	if (config.useldapauth)
		errx(1, "LDAP support configured but not compiled in");
#endif		/* AUTH_LDAP */
#ifndef		HAVE_PCRE
	if (config.usepcreredir)
		errx(1, "PCRE support configured but not compiled in");
#endif		/* HAVE_PCRE */

	/* Set up system section */
	if (!config.system)
	{
		config.system = malloc(sizeof(struct virtual));
		if (!config.system)
			err(1, "Fatal error");
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
	if (!config.system->indexfiles)
		config.system->indexfiles = defaultindexfiles;
	/* Set up users section */
	if (!config.users)
	{
		config.users = malloc(sizeof(struct virtual));
		if (!config.users)
			err(1, "Fatal error");
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
			errx(1, "illegal virtual block without hostname");
		if (!current->htmldir)
			errx(1, "illegal virtual block without directory");
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
		if (!current->indexfiles)
			current->indexfiles = config.system->indexfiles;
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

	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); setegid(origegid);
	}
	else
	{
		savedeuid = config.system->userid;
		savedegid = config.system->groupid;
	}
	if (mainhttpd)
	{
		snprintf(buffer, XS_PATH_MAX, "%s", calcpath(config.pidfile));
		if ((pidlog = fopen(buffer, "w")))
		{
			fprintf(pidlog, "%ld\n", (long)getpid());
			fprintf(pidlog, "%s\n", startparams);
			fclose(pidlog);
		}
		else
			warn("cannot open pidfile %s", config.pidfile);
		/* the master reloads, the children die */
		signal(SIGHUP, SIG_IGN);
		killpg(0, SIGHUP);
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

void
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

void
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
		stdheaders(1, 1, 0);
		if ((env = getenv("HTTP_ALLOW")))
			secprintf("Allow: %s\r\n", env);
	}
	if (!headonly)
	{
		secprintf("\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		secprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
		secprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
		secprintf("\r\n<head><title>%s</title></head>\n", message);
		secprintf("<body><h1>%s</h1></body></html>\n", message);
	}
	fflush(stdout); fflush(stderr); alarm(0);
}

void
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
		secprintf("\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		secprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
		secprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
		secprintf("<head><title>Document has moved</title></head>\n");
		secprintf("<body><h1>Document has moved</h1>\n");
		secprintf("<p>This document has %s moved to ",
			permanent ?  "permanently" : "");
		secprintf("<a href=\"%s%s%s\">%s</a>.</p></body></html>\n",
			redir, env ? "?" : "", env ? env : "", redir);
	}
	fflush(stdout);
}


int
check_auth(FILE *authfile)
{
	char		*search, line[MYBUFSIZ], compare[MYBUFSIZ], *find;

	if (!authentication[0] ||
		strncasecmp(authentication, "Basic", 5))
	{
		if (headers)
		{
			secprintf("%s 401 Unauthorized\r\n", version);
			secprintf("WWW-authenticate: basic realm=\"this page\"\r\n");
			stdheaders(1, 1, 1);
		}
		secprintf("\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		secprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
		secprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
		secprintf("<head><title>Unauthorized</title></head>\n");
		secprintf("<body><h1>Unauthorized</h1><p>Your client \n");
		secprintf("does not understand authentication</body></html>\n");
		fclose(authfile); return(1);
	}
	strlcpy(line, authentication, MYBUFSIZ);
	find = line + strlen(line);
	while ((find > line) && (*(find - 1) < ' '))
		*(--find) = 0;
	for (search = line + 5; *search && isspace(*search); search++)
		/* DO NOTHING */ ;
	uudecode(search);
	if ((find = strchr(search, ':')))
	{
		*find++ = 0;
		setenv("AUTH_TYPE", "Basic", 1);
		setenv("REMOTE_USER", search, 1);
		setenv("REMOTE_PASSWORD", find, 1);

#ifdef AUTH_LDAP
		/*
		 * Try to do an LDAP auth first. This is because xs_encrypt()
		 * may alter the buffer, in which case we compare garbage.
		 */
		if (config.useldapauth &&
			!check_auth_ldap(authfile, search, find))
		{
			return(0);
		}
		rewind (authfile);
#endif /* AUTH_LDAP */

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
	secprintf("\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	secprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
	secprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
	secprintf("<head><title>Wrong password</title></head>\n");
	secprintf("<body><h1>Wrong user/password combination</h1>\n");
	secprintf("You don't have permission to view this page.\n");
	secprintf("</body></html>\n");
	fclose(authfile);
	return(1);
}

void
server_error(const char *readable, const char *cgi)
{
	struct	stat		statbuf;
	char				cgipath[XS_PATH_MAX],
				*escaped, *temp, filename[] = "/error";
	const	char		*env;
	const	struct	passwd	*userinfo;

	if (!current)
		current = config.system;
	if (headonly || getenv("ERROR_CODE"))
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

void
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
	else if (current->logstyle == virtual)
		/* this is combined format + virtual hostname */
		fprintf(alog, "%s %s - - [%s +0000] \"%s %s %s\" 200 %ld "
				"\"%s\" \"%s\"\n",
			current ? current->hostname : config.system->hostname,
			remotehost,
			buffer,
			getenv("REQUEST_METHOD"), dynrequest, version,
			size > 0 ? (long)size : (long)0,
			referer,
			dynagent);
	else /* logstyle = combined */
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

static	void
process_request()
{
	char		line[MYBUFSIZ], extra[MYBUFSIZ], *temp, ch,
			*params, *url, *ver, http_host[NI_MAXHOST],
			http_host_long[NI_MAXHOST];
	int		readerror;
	size_t		size;

	strlcpy(version, "HTTP/0.9", 16);
	strlcpy(dateformat, "%a %b %e %H:%M:%S %Y", MYBUFSIZ);
	orig[0] = referer[0] = line[0] =
		real_path[0] = browser[0] = authentication[0] = '\0';
	headonly = postonly = headers = 0;
	unsetenv("SERVER_NAME"); unsetenv("REQUEST_METHOD");
	unsetenv("CONTENT_LENGTH"); unsetenv("AUTH_TYPE");
	unsetenv("CONTENT_TYPE"); unsetenv("QUERY_STRING");
	unsetenv("PATH_INFO"); unsetenv("PATH_TRANSLATED");
	unsetenv("ORIG_PATH_INFO"); unsetenv("ORIG_PATH_TRANSLATED");
	unsetenv("SCRIPT_FILENAME");
	unsetenv("USER"); unsetenv("HOME"); unsetenv("PWD");
	unsetenv("ERROR_CODE"); unsetenv("ERROR_READABLE");
	unsetenv("ERROR_URL"); unsetenv("ERROR_URL_ESCAPED");
	unsetenv("ERROR_URL_EXPANDED"); unsetenv("REMOTE_USER");
	unsetenv("REMOTE_PASSWORD");
	unsetenv("HTTP_REFERER"); unsetenv("HTTP_COOKIE");
	unsetenv("HTTP_ACCEPT"); unsetenv("HTTP_ACCEPT_ENCODING");
	unsetenv("HTTP_ACCEPT_LANGUAGE"); unsetenv("HTTP_HOST");
	unsetenv("HTTP_NEGOTIONATE"); unsetenv("HTTP_PRAGMA");
	unsetenv("HTTP_CLIENT_IP"); unsetenv("HTTP_VIA");
	unsetenv("HTTP_AUTHORIZATION"); unsetenv("HTTP_ALLOW");
	unsetenv("IF_MODIFIED_SINCE"); unsetenv("IF_UNMODIFIED_SINCE");
	unsetenv("IF_RANGE");
	unsetenv("SSL_CIPHER");

	http_host[0] = '\0';

	alarm(180); errno = 0;
	setreadmode(READCHAR, 1);
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
	setreadmode(strncasecmp("POST", line, 4) ? READBLOCK : READCHAR, 0);
	if (readline(0, line + 4) == ERR_QUIT)
	{
		error("400 Unable to read request line");
		return;
	}
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
			strlcpy(version, "HTTP/1.0", 16);
		}
		else
		{
			headers = 11;
			strlcpy(version, "HTTP/1.1", 16);
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
				strlcpy(browser, param, MYBUFSIZ);
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
				strlcpy(referer, param, MYBUFSIZ);
				while (referer[0] &&
					referer[strlen(referer) - 1] <= ' ')
					referer[strlen(referer) - 1] = 0;
				setenv("HTTP_REFERER", referer, 1);
			} else if (!strcasecmp("Authorization", extra))
			{
				strlcpy(authentication, param, MYBUFSIZ);
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
		strlcpy(version, "HTCPCP/1.0", 16);
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
	{
		error("500 Cannot process request");
		return;
	}

	strlcpy(orig, params, MYBUFSIZ);
	size = strlen(orig);

	if (size < NI_MAXHOST &&
		sscanf(params, "http://%[^/]%c", http_host, &ch) == 2 &&
		ch == '/')
	{
		/* absoluteURI's are supported by HTTP/1.1,
		 * this syntax is preferred over Host-headers(!)
		 */
		setenv("HTTP_HOST", http_host, 1);
		params += strlen(http_host) + 7;
		strlcpy(orig, params, MYBUFSIZ);
	}
	else if (params[0] != '/' && strcmp("OPTIONS", line))
	{
		server_error("400 Relative URL's are not supported", "BAD_REQUEST");
		return;
	}
	/* SERVER_NAME may be overriden soon */
	setenv("SERVER_NAME", config.system->hostname, 1);
	if ((temp = getenv("HTTP_HOST")))
	{
		strlcpy(http_host, temp, NI_MAXHOST);
		for (temp = http_host; *temp; temp++)
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
		if (strcmp(cursock->port, cursock->usessl ? "https" : "http") &&
			strcmp(cursock->port, cursock->usessl ? "443" : "80"))
		{
			if (strlen(http_host) >= NI_MAXHOST - 6)
			{
				server_error("400 Invalid Host Header", "BAD_REQUEST");
				return;
			}
			strlcat(http_host, ":", NI_MAXHOST);
			strlcat(http_host, cursock->port, NI_MAXHOST);
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
	{
		strlcpy(http_host_long, http_host, NI_MAXHOST);
		*temp = '\0';
	}
	else
	{
		snprintf(http_host_long, NI_MAXHOST, "%s:%s",
			http_host, cursock->port);
	}
	for (current = config.virtual; current; current = current->next)
		if (!strcasecmp(http_host_long, current->hostname) ||
			!strcasecmp(http_host, current->hostname))
		{
			break;
		}
		else if (current->aliases)
		{
			char	**aliasp;
			for (aliasp = current->aliases; *aliasp; aliasp++)
				if (!strcasecmp(http_host_long, *aliasp) ||
					!strcasecmp(http_host, *aliasp))
					break;
			if (*aliasp)
				break;
		}
	if (params[0] && params[1] == '~')
		current = config.users;
	else if (!current)
		current = config.system;

	setenv("REQUEST_METHOD", line, 1);
	if (!strcasecmp("GET", line))
		do_get(params);
	else if (!strcasecmp("HEAD", line))
		do_head(params);
	else if (!strcasecmp("POST", line))
		do_post(params);
	else if (!strcasecmp("OPTIONS", line))
		do_options(params);
	/*
	else if (!strcasecmp("PUT", line))
		do_put(params);
	else if (!strcasecmp("DELETE", line))
		do_delete(params);
	else if (!strcasecmp("TRACE", line))
		do_trace(params);
	*/
	else
		server_error("400 Unknown method", "BAD_REQUEST");
}

static	void
standalone_main()
{
	char			id = 'A';

	detach(); open_logs(0);

	for (cursock = config.sockets; cursock; cursock = cursock->next)
	{
		if (cursock->next)
			/* spawn auxiliary master */
			switch (fork())
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
standalone_socket(int id)
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

	setproctitle("xs(MAIN): Initializing deamons...");

#ifdef		HAVE_GETADDRINFO
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = cursock->family;
#ifdef		__linux__
	if (PF_UNSPEC == cursock->family)
#ifdef		INET6
		hints.ai_family = PF_INET6;
#else		/* INET6 */
		hints.ai_family = PF_INET;
#endif		/* INET6 */
#endif		/* __linux__ */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((getaddrinfo(cursock->address ? cursock->address : NULL,
			cursock->port, &hints, &res)))
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
	if (!strcmp(cursock->port, "http"))
		sport = 80;
	else if (!strcmp(cursock->port, "https"))
		sport = 443;
	else
		sport = atoi(cursock->port) || 80;
	((struct sockaddr_in *)&saddr)->sin_port = htons(sport);

	if (bind(sd, &saddr, sizeof(struct sockaddr)) == -1)
		err(1, "bind()");
#endif		/* HAVE_GETADDRINFO */

	if (listen(sd, MAXLISTEN))
		err(1, "listen()");

	if (cursock->usessl)
		loadssl();

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
	if (!(childs = (pid_t *)malloc(sizeof(pid_t) * cursock->instances)))
		err(1, "malloc() failed");

	for (count = 0; count < cursock->instances; count++)
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
		setproctitle("xs(MAIN-%c): Waiting for dead children", id);
		while (mysleep(30))
			/* NOTHING HERE */;
		setproctitle("xs(MAIN-%c): Searching for dead children", id);
		for (count = 0; count < cursock->instances; count++)
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
		if (count > cursock->instances || count < 0)
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

		setproctitle("xs(%c%d): [Reqs: %06d] Setting up myself to accept a connection",
			id, count + 1, reqs);
		if (!origeuid && (seteuid(origeuid) == -1))
			err(1, "seteuid(%ld) failed", (long)origeuid);
		if (!origeuid && (setegid(origegid) == -1))
			err(1, "setegid(%ld) failed", (long)origegid);
		filedescrs();
		setproctitle("xs(%c%d): [Reqs: %06d] Waiting for a connection...",
			id, count + 1, reqs);
		clen = sizeof(saddr);
		if ((csd = accept(sd, (struct sockaddr *)&saddr, &clen)) < 0)
		{
			warn("accept() error %d", errno);
			mysleep(1);
			if (errno == EINTR)
				child_handler(SIGCHLD);
			if (errno == EBADF || errno == EFAULT)
				exit(1);
			continue;
		}
		setproctitle("xs(%c%d): [Reqs: %06d] accept() gave me a connection...",
			id, count + 1, reqs);
		if (fcntl(csd, F_SETFL, 0))
			warn("fcntl() in standalone_main");

		sl.l_onoff = 1; sl.l_linger = 600;
		setsockopt(csd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

		dup2(csd, 0); dup2(csd, 1);
		if (!cursock->usessl)
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
		snprintf(remotehost, NI_MAXHOST, "%d.%d.%d.%d",
			(laddr & 0xff000000) >> 24,
			(laddr & 0x00ff0000) >> 16,
			(laddr & 0x0000ff00) >> 8,
			(laddr & 0x000000ff));
		setenv("REMOTE_HOST", remotehost, 1);
#endif		/* HAVE_GETNAMEINFO */

#ifdef		HAVE_GETNAMEINFO
#ifndef		BROKEN_GETNAMEINFO
		if (!config.usednslookup ||
			!getnameinfo((struct sockaddr *)&saddr, clen,
				remotehost, sizeof(remotehost), NULL, 0, 0))
		{
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
		initssl(csd);
		setproctitle("xs(%d): Connect from `%s'", count + 1, remotehost);
		setcurrenttime();
		if (message503[0])
		{
			alarm(180);
			secprintf("HTTP/1.1 503 Busy\r\nContent-type: text/plain\r\n\r\n");
			secprintf("%s\r\n", message503);
		} else
			process_request();
		alarm(0); reqs++;
		endssl(csd);
		fflush(stdout); fflush(stdin); fflush(stderr);
	}
	/* NOTREACHED */
}

static	void
setup_environment()
{
	/* start with empty environment */
	environ = (char **)malloc(sizeof(char *));
	if (!environ)
		err(1, "Fatal init error");
	*environ = NULL;

	setenv("SERVER_SOFTWARE", SERVER_IDENT, 1);
	setenv("SERVER_NAME", config.system->hostname, 1);
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	setenv("SERVER_PORT", "80", 1);
	setenv("HTTPD_ROOT", config.systemroot, 1);
}

int
main(int argc, char **argv)
{
	int			option, num;
	int			nolog = 0;
	enum { optionp, optiond, optionhd, optionhn, optionaa, optionrr, optionee };
	char *		longopt[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, };
	uid_t		uid = 0;
	gid_t		gid = 0;
#ifdef		HAVE_UNAME
	struct utsname		utsname;
#endif		/* HAVE_UNAME */
	const struct passwd	*userinfo;
	const struct group	*groupinfo;

	origeuid = geteuid(); origegid = getegid();
	memset(&config, 0, sizeof config);

	for (num = option = 0; option < argc; option++)
		num += (1 + strlen(argv[option]));
	if (!(startparams = (char *)malloc(num)))
		err(1, "Cannot malloc memory for startparams");
	*startparams = 0;
	for (option = 0; option < argc; option++)
	{
		strlcat(startparams, argv[option], num);
		if (option < argc - 1)
			strlcat(startparams, " ", num);
	}

	message503[0] = 0;
#ifdef		THISDOMAIN
	strlcpy(thisdomain, THISDOMAIN, NI_MAXHOST);
#else		/* Not THISDOMAIN */
	thisdomain[0] = 0;
#endif		/* THISDOMAIN */
	snprintf(config_path, XS_PATH_MAX, "%s/httpd.conf", calcpath(HTTPD_ROOT));
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
			errx(1, "Option not supported: "
				"set SSL options in httpd.conf");
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
			strlcpy(thisdomain, optarg, NI_MAXHOST);
			break;
		case 'l':
			errx(1, "-l is deprecated: use Users/HtmlDir");
			break;
		case 'm':
			strlcpy(message503, optarg, MYBUFSIZ);
			break;
		case 'c':
			strlcpy(config_path, optarg, XS_PATH_MAX);
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
			strlcpy(config_path, "/dev/null", XS_PATH_MAX);
			break;
		case 'v':
			printf("%s", SERVER_IDENT);
#ifdef		HAVE_UNAME
			uname(&utsname);
			printf(" %s/%s", utsname.sysname, utsname.release);
#endif		/* HAVE_UNAME */
#ifdef		OPENSSL_VERSION_NUMBER
			if (OPENSSL_VERSION_NUMBER >> 4 & 0xff)
				printf(" OpenSSL/%lu.%lu.%lu%c",
					OPENSSL_VERSION_NUMBER >> 28 & 0xf,
					OPENSSL_VERSION_NUMBER >> 20 & 0xff,
					OPENSSL_VERSION_NUMBER >> 12 & 0xff,
					'a' - 1 + (unsigned char)(OPENSSL_VERSION_NUMBER >> 4 & 0xff));
			else
				printf(" OpenSSL/%lu.%lu.%lu",
					OPENSSL_VERSION_NUMBER >> 28 & 0xf,
					OPENSSL_VERSION_NUMBER >> 20 & 0xff,
					OPENSSL_VERSION_NUMBER >> 12 & 0xff);
#endif		/* OPENSSL_VERSION_NUMBER */
#ifdef		PCRE_MAJOR
			printf(" PCRE/%u.%u", PCRE_MAJOR, PCRE_MINOR);
#endif		/* PCRE_MINOR */
			printf("\nCompiled options:\n\t"
#ifdef		INET6
				"+INET6 "
#else		/* INET6 */
				"-INET6 "
#endif		/* INET6 */
#ifdef		WANT_SSI
				"+SSI "
#else		/* WANT_SSI */
				"-SSI "
#endif		/* WANT_SSI */
#ifdef		HANDLE_SSL
				"+SSL "
#else		/* HANDLE_SSL */
				"-SSL "
#endif		/* HANDLE_SSL */
#ifdef		HAVE_CRYPT
				"+CRYPT "
#else		/* HAVE_CRYPT */
				"-CRYPT "
#endif		/* HAVE_CRYPT */
#ifdef		HAVE_MD5
				"+MD5 "
#else		/* HAVE_MD5 */
				"-MD5 "
#endif		/* HAVE_MD5 */
#ifdef		HAVE_PCRE
				"+PCRE "
#else		/* HAVE_PCRE */
				"-PCRE "
#endif		/* HAVE_PCRE */
#ifdef		HANDLE_PERL
				"+PERL "
#else		/* HANDLE_PERL */
				"-PERL "
#endif		/* HANDLE_PERL */
#ifdef		AUTH_LDAP
				"+LDAP "
#else		/* AUTH_LDAP */
				"-LDAP "
#endif		/* AUTH_LDAP */
				"\nDefault configuration file:\n\t%s\n",
				config_path);
			return 0;
		default:
			errx(1, "Usage: httpd [-u username] [-g group] [-p port] [-n number]\n[-d rootdir] [-D documentdir] [-r refer-ignore-domain] [-l localmode]\n[-A access_log] [-E error_log] [-R referrer_log] [-m service-message] [-v]");
		}
	}
	load_config();

#ifdef		HAVE_SETPRIORITY
	if (setpriority(PRIO_PROCESS, (pid_t)0, config.priority))
		warn("setpriority");
#endif		/* HAVE_SETPRIORITY */

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

#ifndef		HAVE_SETPROCTITLE
	initproctitle(argc, argv);
#endif		/* HAVE_SETPROCTITLE */
	setup_environment();
	standalone_main();
	(void)copyright;
	return 0;
}
