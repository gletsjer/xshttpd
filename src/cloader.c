/* Copyright (C) 1998-2007 by Johan van Selst (johans@stack.nl) */
/* $Id$ */

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
#ifdef		HAVE_INTTYPES_H
#include	<inttypes.h>
#endif		/* HAVE_INTTYPES_H */

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
#include	<stdlib.h>
#include	<stdarg.h>
#include	<string.h>
#include	<signal.h>
#include	<pwd.h>
#include	<grp.h>
#include	<unistd.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<ctype.h>
#ifdef		HAVE_PERL
#include	<EXTERN.h>
#include	<perl.h>
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
#include	<python2.5/Python.h>
#endif		/* HAVE_PYTHON */

#include	"htconfig.h"
#include	"httpd.h"
#include	"cloader.h"
#include	"extra.h"
#include	"path.h"

char			config_path[XS_PATH_MAX];
char			config_preprocessor[XS_PATH_MAX];

struct configuration	config;
struct virtual		*current;

#ifdef		HAVE_PERL
PerlInterpreter *	my_perl = NULL;
#endif		/* HAVE_PERL */

void
load_config()
{
	typedef enum	{ sub_none = 0, sub_socket, sub_system,
				sub_virtual, sub_users } subtype_t;
	subtype_t	subtype = sub_none;
	FILE	*confd;
	char	line[LINEBUFSIZE], thishostname[NI_MAXHOST];
	char	*key, *value;
	char	*comment, *end, *username = NULL, *groupname = NULL;
	char	**defaultindexfiles;
	struct passwd	*pwd;
	struct group	*grp;
	struct virtual	*last = NULL;
	struct socket_config	*lsock;

	/* default socket for backwards compatibility */
	lsock = malloc(sizeof(struct socket_config));
	if (!lsock)
		err(1, "Fatal error");
	memset(lsock, 0, sizeof(struct socket_config));
	if (config.instances)
		lsock->instances = config.instances;

	/* Set simple defaults - others follow the parsing */
	config.usednslookup = 1;
	config.usessi = 1;
	config.execasuser = 1;
	config.scriptcpulimit = 2;
	config.scripttimeout = 6;
	config.sockets = NULL;
	config.priority = 0;
	config.scriptpriority = PRIO_MAX;
	config.virtualhostdir = NULL;

	defaultindexfiles = malloc(4 * sizeof(char *));
	defaultindexfiles[0] = strdup(INDEX_HTML);
	defaultindexfiles[1] = strdup("index.htm");
	defaultindexfiles[2] = strdup("index.php");
	defaultindexfiles[3] = NULL;

	if (*config_preprocessor)
	{
		char	*preproccmd;

		asprintf(&preproccmd, "%s %s", config_preprocessor, config_path);
		confd = popen(preproccmd, "r");
		free(preproccmd);
	}
	else
		confd = fopen(config_path, "r");

	if (confd)
	{
		/* skip this loop if there is no config file and use defaults below */
		while (fgets(line, LINEBUFSIZE, confd))
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
				if (!subtype)
				{
					if (!strcasecmp("SystemRoot", key))
					{
						if (!config.systemroot)
							config.systemroot = strdup(value);
					}
					else if (!strcasecmp("PidFile", key))
						config.pidfile = strdup(value);
					else if (!strcasecmp("ExecAsUser", key))
						if (!strcasecmp("true", value))
							config.execasuser = 1;
						else
							config.execasuser = 0;
					else if (!strcasecmp("DefaultCharset", key))
						config.defaultcharset = strdup(value);
					else if (!strcasecmp("UseVirtualUid", key))
						config.usevirtualuid = !strcasecmp("true", value);
					else if (!strcasecmp("UseDnsLookup", key))
						config.usednslookup = !strcasecmp("true", value);
					else if (!strcasecmp("VirtualHostDir", key))
						config.virtualhostdir = strdup(value);
					else if (!strcasecmp("UseLocalScript", key))
						config.uselocalscript = !strcasecmp("true", value);
					else if (!strcasecmp("UseAcceptFilter", key))
						config.useacceptfilter = !strcasecmp("true", value);
					else if (!strcasecmp("UseServerSideInclude", key))
						config.usessi = !strcasecmp("true", value);
					else if (!strcasecmp("UseStrictHostname", key))
						config.usestricthostname = !strcasecmp("true", value);
					else if (!strcasecmp("UseCoreDump", key))
						config.usecoredump = !strcasecmp("true", value);
					else if (!strcasecmp("UseETag", key))
						config.useetag = !strcasecmp("true", value);
					else if (!strcasecmp("UseContentMD5", key))
						config.usecontentmd5 = !strcasecmp("true", value);
					else if (!strcasecmp("ScriptCpuLimit", key))
						config.scriptcpulimit = atoi(value);
					else if (!strcasecmp("ScriptTimeout", key))
						config.scripttimeout = atoi(value);
					else if (!strcasecmp("ScriptEnvPath", key))
						config.scriptpath = strdup(value);
					else if (!current &&
							(!strcasecmp("UserId", key) ||
							 !strcasecmp("GroupId", key)))
						errx(1, "%s directive should be in <System> section", key);
					else if (!strcasecmp("Priority", key))
						config.priority = atoi(value);
					else if (!strcasecmp("ScriptPriority", key))
						config.scriptpriority = atoi(value);
				}
				else if (subtype == sub_socket)
				{
					if (!strcasecmp("ListenAddress", key))
						lsock->address = strdup(value);
					else if (!strcasecmp("ListenPort", key))
						lsock->port = strdup(value);
					else if (!strcasecmp("ListenFamily", key))
						lsock->family =
							!strcasecmp("IPv4", value) ? PF_INET :
							!strcasecmp("IPv6", value) ? PF_INET6 :
							PF_UNSPEC;
					else if (!strcasecmp("SocketName", key))
						lsock->socketname = strdup(value);
					else if (!strcasecmp("Instances", key))
					{
						if (!lsock->instances)
							lsock->instances = atoi(value);
					}
					else if (!strcasecmp("UseSSL", key))
						if (!strcasecmp("true", value))
							lsock->usessl = 1;
						else
							lsock->usessl = 0;
					else if (!strcasecmp("SSLCertificate", key))
					{
						lsock->usessl = 1;
						lsock->sslcertificate =
							strdup(value);
					}
					else if (!strcasecmp("SSLPrivateKey", key))
					{
						lsock->usessl = 1;
						lsock->sslprivatekey =
							strdup(value);
					}
					else if (!strcasecmp("SSLCAfile", key))
						lsock->sslcafile = strdup(value);
					else if (!strcasecmp("SSLCApath", key))
						lsock->sslcapath = strdup(value);
					else if (!strcasecmp("SSLMatchSDN", key))
						lsock->sslmatchsdn = strdup(value);
					else if (!strcasecmp("SSLMatchIDN", key))
						lsock->sslmatchidn = strdup(value);
					else if (!strcasecmp("SSLAuthentication", key))
					{
						if (!strcasecmp(value, "optional"))
							lsock->sslauth = auth_optional;
						else if (!strcasecmp(value, "strict"))
							lsock->sslauth = auth_strict;
						/* default: auth_none */
					}
				}
				/* All other settings belong to specific 'current' */
				else if (!current)
					errx(1, "illegal global directive: '%s'", key);
				else if (subtype != sub_system &&
						subtype != sub_users &&
						subtype != sub_virtual)
					errx(1, "illegal directive: '%s'", key);
				else if (!strcasecmp("Hostname", key))
					current->hostname = strdup(value);
				else if (!strcasecmp("HostAlias", key))
					string_to_arraypn(value, &current->aliases);
				else if (!strcasecmp("PathInfoScripts", key))
					string_to_arraypn(value, &current->uidscripts);
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
				else if (!strcasecmp("LogRefererIgnoreDomain", key))
					current->thisdomain = strdup(value);
				else if (!strcasecmp("IndexFiles", key))
					string_to_arraypn(value, &current->indexfiles);
				else if (!strcasecmp("LogStyle", key))
					if (!strcasecmp("common", value) ||
							!strcasecmp("traditional", value))
						current->logstyle = log_traditional;
					else if (!strcasecmp("combined", value) ||
							 !strcasecmp("extended", value))
						current->logstyle = log_combined;
					else if (!strcasecmp("virtual", value))
						current->logstyle = log_virtual;
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
				else if (!strcasecmp("SocketName", key))
					current->socketname = strdup(value);
				else if (!strcasecmp("LocalMode", key) ||
						!strcasecmp("UseCharset", key) ||
						!strcasecmp("UseRestrictAddr", key) ||
						!strcasecmp("UseVirtualHost", key) ||
						!strcasecmp("UsePcreRedir", key) ||
						!strcasecmp("UseLdapAuth", key))
					warnx("Configuration option '%s' is deprecated",
						key);
				else
					errx(1, "illegal directive: '%s'", key);
			}
			else if (strlen(key))
			{
				if (!strcasecmp("<System>", key))
				{
					if (subtype)
						errx(1, "illegal <System> nesting");
					subtype = sub_system;
					current = malloc(sizeof(struct virtual));
					if (!current)
						err(1, "Fatal error");
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Users>", key))
				{
					if (subtype)
						errx(1, "illegal <Users> nesting");
					subtype = sub_users;
					current = malloc(sizeof(struct virtual));
					if (!current)
						err(1, "Fatal error");
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Virtual>", key))
				{
					if (subtype)
						errx(1, "illegal <Virtual> nesting");
					subtype = sub_virtual;
					current = malloc(sizeof(struct virtual));
					if (!current)
						err(1, "Fatal error");
					memset(current, 0, sizeof(struct virtual));
				}
				else if (!strcasecmp("<Socket>", key))
				{
					if (subtype)
						errx(1, "illegal <Socket> nesting");
					subtype = sub_socket;
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
					if (subtype != sub_system)
						errx(1, "</System> end without start");
					if (config.system)
						errx(1, "duplicate <System> definition");
					subtype = sub_none;
					config.system = current;
					current = NULL;
				}
				else if (!strcasecmp("</Users>", key))
				{
					if (subtype != sub_users)
						errx(1, "</Users> end without start");
					if (config.users)
						errx(1, "duplicate <Users> definition");
					subtype = sub_none;
					config.users = current;
					current = NULL;
				}
				else if (!strcasecmp("</Virtual>", key))
				{
					if (subtype != sub_virtual)
						errx(1, "</Virtual> end without start");
					subtype = sub_none;
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
					if (subtype != sub_socket)
						errx(1, "</Socket> end without start");
					subtype = sub_none;
				}
				else
					errx(1, "illegal directive: '%s'", key);
			}
			else
				errx(1, "illegal directive: '%s'", line);
		}
		if (*config_preprocessor)
			pclose(confd);
		else
			fclose(confd);
	}
	else
		warn("Not reading configuration file");

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
#ifndef		HANDLE_SSL
			/* Sanity check */
			errx(1, "SSL support configured but not compiled in");
#endif		/* HANDLE_SSL */
		}
	}
	if (!config.pidfile)
		config.pidfile = strdup(PID_PATH);
	if (!config.scriptpath)
		config.scriptpath = strdup(SCRIPT_PATH);

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
		config.system->htmldir = strdup(HTML_DIR);
	if (!config.system->execdir)
		config.system->execdir = strdup(CGI_DIR);
	if (!config.system->phexecdir)
		config.system->phexecdir = strdup(PHEXEC_DIR);
	if (!config.system->icondir)
		config.system->icondir = strdup(ICON_DIR);
	if (!config.system->logaccess)
		config.system->logaccess = strdup(BITBUCKETNAME);
	if (!config.system->logerror)
		config.system->logerror = strdup(BITBUCKETNAME);
	if (!config.system->logreferer)
		config.system->logreferer = strdup(BITBUCKETNAME);
	if (!config.system->logstyle)
		config.system->logstyle = log_combined;
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
		config.users->htmldir = strdup(UHTML_DIR);
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
			current->execdir = strdup(CGI_DIR);
		if (!current->phexecdir)
			current->phexecdir = strdup(PHEXEC_DIR);
		if (!current->icondir)
			current->icondir = strdup(calcpath(ICON_DIR));
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

void
remove_config()
{
	/* XXX: Rewrite this to avoid memory leaks */
	memset(&config, '\0', sizeof config);
}

#ifdef		HAVE_PERL
void
loadperl()
{
	char *path, *embedding[] = { NULL, NULL };
	int exitstatus = 0;

	if (!(my_perl = perl_alloc()))
		err(1, "No memory!");
	perl_construct(my_perl);

	/* perl_parse() doesn't like const arguments: pass dynamic */
	path = strdup(HTTPD_ROOT "/persistent.pl");
	embedding[0] = embedding[1] = path;
	exitstatus = perl_parse(my_perl, NULL, 2, embedding, NULL);
	free(path);
	if (!exitstatus)
		exitstatus = perl_run(my_perl);
	else
		err(1, "No perl!");
}
#endif		/* HAVE_PERL */

#ifdef		HAVE_PYTHON
void
loadpython()
{
	Py_InitializeEx(0);
}
#endif		/* HAVE_PYTHON */


