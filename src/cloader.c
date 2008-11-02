/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<inttypes.h>
#include	<stdbool.h>
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
#include	"malloc.h"
#include	"ssl.h"

#ifndef		PRIO_MAX
#define		PRIO_MAX	20
#endif

char			*config_path;
char			*config_preprocessor;

struct configuration	config;
struct virtual		*current;

#ifdef		HAVE_PERL
PerlInterpreter *	my_perl = NULL;
#endif		/* HAVE_PERL */

#ifdef		HAVE_RUBY
extern void	ruby_init(void);
extern void	ruby_script(const char *);
#endif		/* HAVE_RUBY */

void
load_config()
{
	FILE	*confd;
	char	thishostname[NI_MAXHOST];
	struct socket_config	*lsock;
	static const char	*defaultindexfiles[] =
		{ INDEX_HTML, "index.htm", "index.xhtml", "index.xml",
		  "index.php", NULL };
	static const char	*defaultuidscripts[] =
		{ "/cgi-bin/imagemap", "/cgi-bin/xschpass", NULL };

	/* default socket for backwards compatibility */
	CALLOC(lsock, struct socket_config, 1);
	if (config.instances)
		lsock->instances = config.instances;

	/* Set simple defaults - others follow the parsing */
	config.usednslookup = true;
	config.usessi = true;
	config.useput = true;
	config.execasuser = true;
#ifdef		HAVE_SENDFILE
	config.usesendfile = true;
#endif		/* HAVE_SENDFILE */
	config.scriptcpulimit = 2;
	config.scripttimeout = 6;
	config.sockets = NULL;
	config.priority = 0;
	config.scriptpriority = PRIO_MAX;
	config.virtualhostdir = NULL;

	if (config_preprocessor)
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
		typedef enum	{ sub_none = 0, sub_socket, sub_system,
					sub_virtual, sub_users } subtype_t;
		subtype_t	subtype = sub_none;
		struct virtual	*last = NULL;
		char		*line;
		size_t		sz;

		/* parse config file */
		while ((line = fgetln(confd, &sz)))
		{
			char	*key, *value, *comment, *end;

			if ((comment = strchr(line, '#')))
				*comment = '\0';
			end = line + sz;
			while ((end > line) && (*(end - 1) <= ' '))
				*(--end) = '\0';
			if (end == line || end == line + sz)
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
							STRDUP(config.systemroot, value);
					}
					else if (!strcasecmp("PidFile", key))
						STRDUP(config.pidfile, value);
					else if (!strcasecmp("ExecAsUser", key))
						if (!strcasecmp("true", value))
							config.execasuser = true;
						else
							config.execasuser = false;
					else if (!strcasecmp("DefaultCharset", key))
						STRDUP(config.defaultcharset, value);
					else if (!strcasecmp("UseVirtualUid", key))
						config.usevirtualuid = !strcasecmp("true", value);
					else if (!strcasecmp("UseDnsLookup", key))
						config.usednslookup = !strcasecmp("true", value);
					else if (!strcasecmp("VirtualHostDir", key))
						STRDUP(config.virtualhostdir, value);
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
					else if (!strcasecmp("UseSendfile", key))
						config.usesendfile = !strcasecmp("true", value);
					else if (!strcasecmp("UseETag", key))
						config.useetag = !strcasecmp("true", value);
					else if (!strcasecmp("UseContentMD5", key))
						config.usecontentmd5 = !strcasecmp("true", value);
					else if (!strcasecmp("UsePut", key))
						config.useput = !strcasecmp("true", value);
					else if (!strcasecmp("ScriptCpuLimit", key))
						config.scriptcpulimit = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptTimeout", key))
						config.scripttimeout = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptEnvPath", key))
						STRDUP(config.scriptpath, value);
					else if (!current &&
							(!strcasecmp("UserId", key) ||
							 !strcasecmp("GroupId", key)))
						errx(1, "%s directive should be in <System> section", key);
					else if (!strcasecmp("Priority", key))
						config.priority = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptPriority", key))
						config.scriptpriority = strtoul(value, NULL, 10);
					else if (!strcasecmp("PerlPersistentScript", key))
						STRDUP(config.perlscript, value);
				}
				else if (subtype == sub_socket)
				{
					if (!strcasecmp("ListenAddress", key))
						STRDUP(lsock->address, value);
					else if (!strcasecmp("ListenPort", key))
						STRDUP(lsock->port, value);
					else if (!strcasecmp("ListenFamily", key))
						lsock->family =
							!strcasecmp("IPv4", value) ? PF_INET :
#ifdef		PF_INET6
							!strcasecmp("IPv6", value) ? PF_INET6 :
#endif		/* PF_INET6 */
							PF_UNSPEC;
					else if (!strcasecmp("SocketName", key))
						STRDUP(lsock->socketname, value);
					else if (!strcasecmp("Instances", key))
					{
						if (!lsock->instances)
							lsock->instances = strtoul(value, NULL, 10);
					}
					else if (!strcasecmp("UseSSL", key))
						if (!strcasecmp("true", value))
							lsock->usessl = true;
						else
							lsock->usessl = false;
					else if (!strcasecmp("SSLCertificate", key))
					{
						lsock->usessl = true;
						STRDUP(lsock->sslcertificate,
							calcpath(value));
					}
					else if (!strcasecmp("SSLPrivateKey", key))
					{
						lsock->usessl = true;
						STRDUP(lsock->sslprivatekey,
							calcpath(value));
					}
					else if (!strcasecmp("SSLCAfile", key))
						STRDUP(lsock->sslcafile, calcpath(value));
					else if (!strcasecmp("SSLCApath", key))
						STRDUP(lsock->sslcapath, calcpath(value));
					else if (!strcasecmp("SSLMatchSDN", key))
						STRDUP(lsock->sslmatchsdn, value);
					else if (!strcasecmp("SSLMatchIDN", key))
						STRDUP(lsock->sslmatchidn, value);
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
					STRDUP(current->hostname, value);
				else if (!strcasecmp("HostAlias", key))
					string_to_arraypn(value, &current->aliases);
				else if (!strcasecmp("PathInfoScripts", key))
					string_to_arraypn(value, &current->uidscripts);
				else if (!strcasecmp("HtmlDir", key))
					STRDUP(current->htmldir, value);
				else if (!strcasecmp("ExecDir", key))
					STRDUP(current->execdir, value);
				else if (!strcasecmp("PhExecDir", key))
					STRDUP(current->phexecdir, value);
				else if (!strcasecmp("IconDir", key))
					STRDUP(current->icondir, calcpath(value));
				else if (!strcasecmp("PhIconDir", key))
					STRDUP(current->phicondir, calcpath(value));
				else if (!strcasecmp("LogAccess", key))
					STRDUP(current->logaccess, value);
				else if (!strcasecmp("LogError", key))
					STRDUP(current->logerror, value);
				else if (!strcasecmp("LogScript", key))
					STRDUP(current->logscript, value);
				else if (!strcasecmp("LogReferer", key))
					STRDUP(current->logreferer, value);
				else if (!strcasecmp("LogRefererIgnoreDomain", key))
					STRDUP(current->thisdomain, value);
				else if (!strcasecmp("RedirFile", key))
					STRDUP(current->redirfile, calcpath(value));
				else if (!strcasecmp("FcgiPath", key))
					STRDUP(current->fcgipath, value);
				else if (!strcasecmp("FcgiSocket", key))
					STRDUP(current->fcgisocket, value);
				else if (!strcasecmp("PhpFcgiChildren", key))
					current->phpfcgichildren = strtoul(value, NULL, 10);
				else if (!strcasecmp("PhpFcgiRequests", key))
					current->phpfcgirequests = strtoul(value, NULL, 10);
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
					if (!current->userid && !(current->userid = strtoul(value, NULL, 10)))
					{
						struct passwd	*pwd;
						if (!(pwd = getpwnam(value)))
							errx(1, "Invalid username: %s", value);
						current->userid = pwd->pw_uid;
					}
				}
				else if (!strcasecmp("GroupId", key))
				{
					if (!current->groupid && !(current->groupid = strtoul(value, NULL, 10)))
					{
						struct group	*grp;
						if (!(grp = getgrnam(value)))
							errx(1, "Invalid groupname: %s", value);
						current->groupid = grp->gr_gid;
					}
				}
				else if (!strcasecmp("SocketName", key))
					STRDUP(current->socketname, value);
				else if (!strcasecmp("LocalMode", key) ||
						!strcasecmp("UseCharset", key) ||
						!strcasecmp("UseRestrictAddr", key) ||
						!strcasecmp("UseVirtualHost", key) ||
						!strcasecmp("UsePcreRedir", key) ||
						!strcasecmp("UseLdapAuth", key))
					warnx("Configuration option '%s' is deprecated",
						key);
				else if (!strcasecmp("SSLCertificate", key))
#ifdef		HANDLE_SSL_TLSEXT
					STRDUP(current->sslcertificate,
						calcpath(value));
#else		/* HANDLE_SSL_TLSEXT */
					errx(1, "Vhost SSLCertificate not allowed: SSL library doesn't support TLSEXT");
#endif		/* HANDLE_SSL_TLSEXT */
				else if (!strcasecmp("SSLPrivateKey", key))
					STRDUP(current->sslprivatekey,
						calcpath(value));
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
					CALLOC(current, struct virtual, 1);
				}
				else if (!strcasecmp("<Users>", key))
				{
					if (subtype)
						errx(1, "illegal <Users> nesting");
					subtype = sub_users;
					CALLOC(current, struct virtual, 1);
				}
				else if (!strcasecmp("<Virtual>", key))
				{
					if (subtype)
						errx(1, "illegal <Virtual> nesting");
					subtype = sub_virtual;
					CALLOC(current, struct virtual, 1);
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
						CALLOC(lsock->next, struct socket_config, 1);
						lsock = lsock->next;
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
		if (config_preprocessor)
			pclose(confd);
		else
			fclose(confd);
	}
	else
		warn("Not reading configuration file");

	/* Fill in missing defaults */
	if (!config.systemroot)
		STRDUP(config.systemroot, HTTPD_ROOT);
	if (!config.sockets)
		config.sockets = lsock;
	for (lsock = config.sockets; lsock; lsock = lsock->next)
	{
		if (!lsock->port)
			STRDUP(lsock->port, lsock->usessl ? "https" : "http");
		if (!lsock->instances)
			lsock->instances = HTTPD_NUMBER;
		if (lsock->usessl)
		{
#ifdef		HANDLE_SSL
			struct virtual	*vc;

			loadssl(lsock, NULL);
			if (lsock->socketname)
				for (vc = config.virtual; vc; vc = vc->next)
					if (vc->socketname &&
						!strcasecmp(lsock->socketname,
							vc->socketname))
						loadssl(lsock, vc);
#else		/* HANDLE_SSL */
			/* Sanity check */
			errx(1, "SSL support configured but not compiled in");
#endif		/* HANDLE_SSL */
		}
	}
	if (!config.pidfile)
		STRDUP(config.pidfile, PID_PATH);
	if (!config.scriptpath)
		STRDUP(config.scriptpath, SCRIPT_PATH);

	/* Set up system section */
	if (!config.system)
		CALLOC(config.system, struct virtual, 1);
	if (!config.system->hostname)
	{
		if (gethostname(thishostname, NI_MAXHOST) == -1)
			errx(1, "gethostname() failed");
		STRDUP(config.system->hostname, thishostname);
	}
	if (!config.system->htmldir)
		STRDUP(config.system->htmldir, HTML_DIR);
	if (!config.system->execdir)
		STRDUP(config.system->execdir, CGI_DIR);
	if (!config.system->phexecdir)
		STRDUP(config.system->phexecdir, PHEXEC_DIR);
	if (!config.system->icondir)
		STRDUP(config.system->icondir, ICON_DIR);
	if (!config.system->phicondir)
		STRDUP(config.system->phicondir, PHICON_DIR);
	if (!config.system->logaccess)
		STRDUP(config.system->logaccess, BITBUCKETNAME);
	if (!config.system->logerror)
		STRDUP(config.system->logerror, BITBUCKETNAME);
	if (!config.system->logreferer)
		STRDUP(config.system->logreferer, BITBUCKETNAME);
	if (!config.system->logstyle)
		config.system->logstyle = log_combined;
	if (!config.system->userid)
	{
		struct passwd	*pwd;

		if (!(pwd = getpwnam(HTTPD_USERID)))
			errx(1, "Invalid username: %s", HTTPD_USERID);
		config.system->userid = pwd->pw_uid;
	}
	if (!config.system->groupid &&
		!(config.system->groupid = strtoul(HTTPD_GROUPID, NULL, 10)))
	{
		struct group	*grp;

		if (!(grp = getgrnam(HTTPD_GROUPID)))
			errx(1, "Invalid groupname: %s", HTTPD_GROUPID);
		config.system->groupid = grp->gr_gid;
	}
	if (!config.system->indexfiles)
	{
		int		i;
		size_t	sz = sizeof(defaultindexfiles) / sizeof(char *);

		MALLOC(config.system->indexfiles, char *, sz);
		for (i = 0; defaultindexfiles[i]; i++)
			STRDUP(config.system->indexfiles[i],
				defaultindexfiles[i]);
		config.system->indexfiles[i] = NULL;
	}
	if (!config.system->uidscripts)
	{
		int		i;
		size_t	sz = sizeof(defaultindexfiles) / sizeof(char *);

		MALLOC(config.system->uidscripts, char *, sz);
		for (i = 0; defaultuidscripts[i]; i++)
			STRDUP(config.system->uidscripts[i],
				defaultuidscripts[i]);
		config.system->uidscripts[i] = NULL;
	}
	/* Set up users section */
	if (!config.users)
		CALLOC(config.users, struct virtual, 1);
	if (!config.users->hostname)
		STRDUP(config.users->hostname, config.system->hostname);
	if (!config.users->htmldir)
		STRDUP(config.users->htmldir, UHTML_DIR);
	config.system->next = config.users;
	config.users->next = config.virtual;
	/* Check users and virtual sections */
	for (current = config.users; current; current = current->next)
	{
		if (!current->hostname)
			errx(1, "illegal virtual block without hostname");
		if (!(!!current->htmldir ^ !!current->redirfile))
			errx(1, "virtual block must contain either htmldir or redirfile");
		if (!current->execdir)
			STRDUP(current->execdir, CGI_DIR);
		if (!current->phexecdir)
			STRDUP(current->phexecdir, PHEXEC_DIR);
		if (!current->icondir)
			STRDUP(current->icondir, calcpath(ICON_DIR));
		if (!current->phicondir)
			STRDUP(current->phicondir, calcpath(PHICON_DIR));
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
	memset(&config, 0, sizeof config);
}

#ifdef		HAVE_PERL
void
loadperl()
{
	char	*path, *embedding[] = { NULL, NULL };
	int	exitstatus = 0;

	if (!(my_perl = perl_alloc()))
		err(1, "No memory!");
	perl_construct(my_perl);

	/* perl_parse() doesn't like const arguments: pass dynamic */
	if (config.perlscript)
		STRDUP(path, calcpath(config.perlscript));
	else
		STRDUP(path, calcpath("contrib/persistent.pl"));
	if (!access(path, R_OK))
	{
		embedding[0] = embedding[1] = path;
		exitstatus = perl_parse(my_perl, NULL, 2, embedding, NULL);
		if (!exitstatus)
		{
			perl_run(my_perl);
			free(path);
			return;
		}
	}

	warn("Perl module not available");
	free(path);
	perl_free(my_perl);
	my_perl = NULL;
}
#endif		/* HAVE_PERL */

#ifdef		HAVE_PYTHON
void
loadpython()
{
	Py_InitializeEx(0);
}
#endif		/* HAVE_PYTHON */

#ifdef		HAVE_RUBY
void
loadruby()
{
	ruby_init();
	ruby_script("embedded");
}
#endif		/* HAVE_RUBY */

