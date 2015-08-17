/* Copyright (C) 1998-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<inttypes.h>
#include	<stdbool.h>
#include	<sys/resource.h>
#include	<sys/mman.h>
#include	<sys/socket.h>
#include	<sys/wait.h>
#include	<sys/signal.h>
#include	<sys/stat.h>
#include	<sys/utsname.h>
#include	<sys/select.h>
#include	<sys/param.h>
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
#ifdef		HAVE_LIBUTIL_H
#include	<libutil.h>
#else		/* HAVE_LIBUTIL_H */
# ifdef		HAVE_UTIL_H
# include	<util.h>
# endif		/* HAVE_UTIL_H */
#endif		/* HAVE_LIBUTIL_H */
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<ctype.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"cloader.h"
#include	"extra.h"
#include	"path.h"
#include	"malloc.h"
#include	"ssl.h"
#include	"modules.h"

#ifndef		PRIO_MAX
#define		PRIO_MAX	20
#endif

#define		PKEYS_MAX	16

char			*config_path;
char			*config_preprocessor;

struct configuration	config;
struct virtual		*current;

struct config_option
{
	const char		*key;
	const char		*value;
	struct config_option	*next;
} *global_options = NULL, *unknown_options = NULL;

static char *checkpath(const char *directive, const char *prefix, const char *value) MALLOC_FUNC;

static char *
checkpath(const char *directive, const char *prefix, const char *value)
{
	char	*result = NULL;

	if (!value)
		errx(1, "Directive '%s' missing argument", directive);

	if (value[0] != '/')
	{
		if (!prefix || prefix[0] != '/')
			errx(1, "Directive '%s' must be absolute pathname", directive);

		ASPRINTF(&result, "%s/%s", prefix, value);
		return result;
	}

	STRDUP(result, value);
	return result;
}
	

void
load_config()
{
	FILE	*confd;
	char	thishostname[NI_MAXHOST];
	struct socket_config	*lsock;
	static const char * const	defaultindexfiles[] =
		{ INDEX_HTML, "index.htm", "index.xhtml", "index.xml",
		  "index.php", NULL };
	static const char * const	defaultuidscripts[] =
		{ "/cgi-bin/imagemap", "/cgi-bin/xschpass", NULL };

	/* default socket for backwards compatibility */
	CALLOC(lsock, struct socket_config, 1);
	if (config.instances)
		lsock->instances = config.instances;

	/* Set simple defaults - others follow the parsing */
	config.usednslookup = true;
	config.usessi = true;
	config.useput = true;
	config.uselocalscript = true;
	config.usetimestamp = true;
	config.usesslsessiontickets = true;
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
	STRDUP(config.serverident, SERVER_IDENT);
	STRDUP(config.proxyident, SERVER_IDENT);

	if (config_preprocessor)
	{
		char	*preproccmd;

		ASPRINTF(&preproccmd, "%s %s", config_preprocessor, config_path);
		confd = popen(preproccmd, "r");
		FREE(preproccmd);
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

		/* parse config file */
		while ((line = fparseln(confd, NULL, NULL, NULL, FPARSEARG)))
		{
			char	*key, *value, *end, *tmp;

			end = strchr(line, '\0');
			while (end > line && *(end - 1) <= ' ')
				*(--end) = '\0';
			if (end <= line)
			{
				FREE(line);
				continue;
			}
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
					bool	unknown_option = false;

					if (!strcasecmp("SystemRoot", key))
						warnx("Ignoring SystemRoot directive: no longer supported");
					else if (!strcasecmp("PidFile", key))
						config.pidfile = checkpath("PidFile", RUN_DIR, value);
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
						config.virtualhostdir = checkpath("VirtualHostDir", WWW_DIR, value);
					else if (!strcasecmp("UseLocalScript", key))
						config.uselocalscript = !strcasecmp("true", value);
					else if (!strcasecmp("UseScriptArgs", key))
						config.usescriptargs = !strcasecmp("true", value);
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
					else if (!strcasecmp("UseTimestamp", key))
						config.usetimestamp = !strcasecmp("true", value);
					else if (!strcasecmp("UsePut", key))
						config.useput = !strcasecmp("true", value);
					else if (!strcasecmp("UseTrace", key))
						config.usetrace = !strcasecmp("true", value);
					else if (!strcasecmp("UseSSLSessionTickets", key))
						config.usesslsessiontickets = !strcasecmp("true", value);
					else if (!strcasecmp("UseSSLSessionStore", key))
						config.usesslsessionstore = !strcasecmp("true", value);
					else if (!strcasecmp("DnsTimeout", key))
						config.dnstimeout = strtoul(value, NULL, 10);
					else if (!strcasecmp("DnsAttempts", key))
						config.dnsattempts = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptCpuLimit", key))
						config.scriptcpulimit = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptTimeout", key))
						config.scripttimeout = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptEnvPath", key))
						STRDUP(config.scriptpath, value);
					else if (!strcasecmp("ScriptUmask", key))
						STRDUP(config.scriptumask, value);
					else if (!current &&
							(!strcasecmp("UserId", key) ||
							 !strcasecmp("GroupId", key)))
						errx(1, "%s directive should be in <System> section", key);
					else if (!strcasecmp("Priority", key))
						config.priority = strtoul(value, NULL, 10);
					else if (!strcasecmp("ScriptPriority", key))
						config.scriptpriority = strtoul(value, NULL, 10);
					else if (!strcasecmp("ServerIdent", key))
					{
						/* Note: copied in ProxyIdent */
						char	*p = NULL;

						if (!strcasecmp("full", value))
							/* .. */;
						else if (!strcasecmp("none", value))
							FREE(config.serverident);
						else if (!strcasecmp("branch", value))
							p = strchr(config.serverident, ' ');
						else if (!strcasecmp("name", value))
							p = strchr(config.serverident, '/');
						if (p)
							*p = '\0';
					}
					else if (!strcasecmp("ProxyIdent", key))
					{
						/* Note: copy of ServerIdent */
						char	*p = NULL;

						if (!strcasecmp("full", value))
							/* .. */;
						else if (!strcasecmp("none", value))
							FREE(config.proxyident);
						else if (!strcasecmp("branch", value))
							p = strchr(config.proxyident, ' ');
						else if (!strcasecmp("name", value))
							p = strchr(config.proxyident, '/');
						if (p)
							*p = '\0';
					}
					else if (!strcasecmp("Modules", key))
						string_to_arraypn(value, &config.modules);
					else
					{
						unknown_option = true;
					}

					/* Might be a module option: store for later */
					struct	config_option	*option;

					MALLOC(option, struct config_option, 1);
					STRDUP(option->key, key);
					STRDUP(option->value, value);
					if (unknown_option)
					{
						option->next = unknown_options;
						unknown_options = option;
					}
					else
					{
						option->next = global_options;
						global_options = option;
					}
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
					else if (!strcasecmp("ListenProtocol", key))
					{
						if (!strcasecmp("SCTP", value))
							lsock->protocol = IPPROTO_SCTP;
						else if (!strcasecmp("TCP", value))
							lsock->protocol = IPPROTO_TCP;
						else
							errx(1, "Invalid value for ListenProtocol");
					}
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
						if (string_to_arraypn(value, &lsock->sslcertificate))
							for (int i = 0; (tmp = lsock->sslcertificate[i]); i++)
							{
								lsock->sslcertificate[i] =
									checkpath("SSLCertificate", CONFIG_DIR, tmp);
								FREE(tmp);
							}
					}
					else if (!strcasecmp("SSLPrivateKey", key))
					{
						lsock->usessl = true;
						if (string_to_arraypn(value, &lsock->sslprivatekey))
							for (int i = 0; (tmp = lsock->sslprivatekey[i]); i++)
							{
								lsock->sslprivatekey[i] =
									checkpath("SSLPrivateKey", CONFIG_DIR, tmp);
								FREE(tmp);
							}
					}
					else if (!strcasecmp("SSLNoCert", key))
						lsock->sslnocert = !strcasecmp("true", value);
					else if (!strcasecmp("SSLCAfile", key))
						lsock->sslcafile = checkpath("SSLCAfile", CONFIG_DIR, value);
					else if (!strcasecmp("SSLCApath", key))
						lsock->sslcapath = checkpath("SSLCApath", CONFIG_DIR, value);
					else if (!strcasecmp("SSLCRLfile", key))
						lsock->sslcrlfile = checkpath("SSLCRLfile", CONFIG_DIR, value);
					else if (!strcasecmp("SSLCRLpath", key))
						lsock->sslcrlpath = checkpath("SSLCRLpath", CONFIG_DIR, value);
					else if (!strcasecmp("SSLOCSPfile", key))
						lsock->sslocspfile = checkpath("SSLOCSPfile", DB_DIR, value);
					else if (!strcasecmp("SSLinfofile", key))
						lsock->sslinfofile = checkpath("SSLinfofile", DB_DIR, value);
					else if (!strcasecmp("SSLCAlist", key))
						STRDUP(lsock->sslcalist, value);
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
					else if (!strcasecmp("SSLCipherList", key))
						STRDUP(lsock->sslcipherlist, value);
					else if (!strcasecmp("SSLTicketKey", key))
						STRDUP(lsock->sslticketkey, value);
					else
						errx(1, "illegal socket directive: '%s'", key);
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
				{
					if (subtype == sub_users)
						STRDUP(current->htmldir, value);
					else
						current->htmldir = checkpath("HtmlDir", WWW_DIR, value);
				}
				else if (!strcasecmp("ExecDir", key))
					STRDUP(current->execdir, value);
				else if (!strcasecmp("PhExecDir", key))
					current->phexecdir = checkpath("PhExecDir", WWW_DIR, value);
				else if (!strcasecmp("IconDir", key))
					STRDUP(current->icondir, value);
				else if (!strcasecmp("PhIconDir", key))
					current->phicondir = checkpath("PhIconDir", SHDATA_DIR, value);
				else if (!strcasecmp("LogAccess", key))
					current->logaccess = checkpath("LogAccess", LOG_DIR, value);
				else if (!strcasecmp("LogError", key))
					current->logerror = checkpath("LogError", LOG_DIR, value);
				else if (!strcasecmp("LogScript", key))
					current->logscript = checkpath("LogScript", LOG_DIR, value);
				else if (!strcasecmp("LogReferer", key))
					current->logreferer = checkpath("LogReferer", LOG_DIR, value);
				else if (!strcasecmp("LogRefererIgnoreDomain", key))
					STRDUP(current->thisdomain, value);
				else if (!strcasecmp("RedirFile", key))
					current->redirfile = checkpath("RedirFile", CONFIG_DIR, value);
				else if (!strcasecmp("FcgiPath", key))
					current->fcgipath = checkpath("FcgiPath", RUN_DIR, value);
				else if (!strcasecmp("FcgiSocket", key))
					current->fcgisocket = checkpath("FcgiSocket", RUN_DIR, value);
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
				else if (!strcasecmp("UseUsers", key))
					if (!strcasecmp("true", value))
						current->allowusers = true;
					else
						current->allowusers = false;
				else if (!strcasecmp("UserId", key))
				{
					if (!current->userid && !(current->userid = strtoul(value, NULL, 10)))
					{
						const struct passwd	*pwd = getpwnam(value);

						if (!pwd)
							errx(1, "Invalid username: %s", value);
						current->userid = pwd->pw_uid;
					}
				}
				else if (!strcasecmp("GroupId", key))
				{
					if (!current->groupid && !(current->groupid = strtoul(value, NULL, 10)))
					{
						struct group	*grp = getgrnam(value);

						if (!grp)
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
						!strcasecmp("UsePcreRedir", key))
					warnx("Configuration option '%s' is deprecated",
						key);
				else if (!strcasecmp("SSLCertificate", key))
#ifdef		HANDLE_SSL_TLSEXT
				{
					if (string_to_arraypn(value, &current->sslcertificate))
						for (int i = 0; (tmp = current->sslcertificate[i]); i++)
						{
							current->sslcertificate[i] =
								checkpath("SSLCertificate", CONFIG_DIR, tmp);
							FREE(tmp);
						}
				}
#else		/* HANDLE_SSL_TLSEXT */
					errx(1, "Vhost SSLCertificate not allowed: SSL library doesn't support TLSEXT");
#endif		/* HANDLE_SSL_TLSEXT */
				else if (!strcasecmp("SSLPrivateKey", key))
				{
					if (string_to_arraypn(value, &current->sslprivatekey))
						for (int i = 0; (tmp = current->sslprivatekey[i]); i++)
						{
							current->sslprivatekey[i] =
								checkpath("SSLPrivateKey", CONFIG_DIR, tmp);
							FREE(tmp);
						}
				}
				else if (!strcasecmp("SSLOCSPfile", key))
					current->sslocspfile = checkpath("SSLOCSPfile", DB_DIR, value);
				else if (!strcasecmp("SSLinfofile", key))
					current->sslinfofile = checkpath("SSLinfofile", DB_DIR, value);
				else if (!strcasecmp("UseSTS", key))
					current->usests = !strcasecmp("true", value);
				else if (!strcasecmp("STSMaxAge", key))
					current->stsmaxage = strtoul(value, NULL, 10);
				else if (!strcasecmp("STSSubDomains", key))
					current->stssubdomains = !strcasecmp("true", value);
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

			FREE(line);
		}
		if (config_preprocessor)
			pclose(confd);
		else
			fclose(confd);
	}
	else
		warn("Not reading configuration file");

	/* Fill in missing defaults */
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
			loadssl(lsock, NULL);

#ifdef		HANDLE_SSL_TLSEXT
			struct ssl_vhost	*vhost = NULL,
								*lasthost = NULL;

			for (struct virtual *vc = config.virtual; vc; vc = vc->next)
			{
				if ((vc->socketname || lsock->socketname) &&
						(!lsock->socketname || !vc->socketname ||
						 strcasecmp(vc->socketname, lsock->socketname)))
					/* vhost not used on this socket */
					continue;
				if (vc->sslcertificate)
				{
					/* add lsock->sslvhost with sslvhost->virtual = vc */
					CALLOC(vhost, struct ssl_vhost, 1);
					vhost->virtual = vc;
					if (lasthost)
					{
						lasthost->next = vhost;
						lasthost = vhost;
					}
					else
						lsock->sslvhosts = lasthost = vhost;
					loadssl(lsock, vhost);
				}
			}
#endif		/* HANDLE_SSL_TLSEXT */
		}
	}
	if (!config.pidfile)
		STRDUP(config.pidfile, PID_FILE);
	if (!config.scriptpath)
		STRDUP(config.scriptpath, SCRIPT_PATH);
#ifndef		HAVE_DB_H
	if (config.usesslsessionstore)
		errx(1, "UseSSLSessionStore not available when compiled without Berkely DB support");
#endif		/* Not HAVE_DB_H */

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
		config.system->htmldir = checkpath("HtmlDir", WWW_DIR, HTML_DIR);
	if (!config.system->execdir)
		STRDUP(config.system->execdir, CGI_DIR);
	if (!config.system->phexecdir)
		config.system->phexecdir = checkpath("ExecDir", WWW_DIR, PHEXEC_DIR);
	if (!config.system->icondir)
		STRDUP(config.system->icondir, ICON_DIR);
	if (!config.system->phicondir)
		config.system->phicondir = checkpath("PhIconDir", SHDATA_DIR, PHICON_DIR);
	if (!config.system->logaccess)
		config.system->logaccess = checkpath("LogAccess", LOG_DIR, "access_log");
	if (!config.system->logerror)
		config.system->logerror = checkpath("LogError", LOG_DIR, "error_log");
	if (!config.system->logreferer)
		config.system->logreferer = checkpath("LogReferer", LOG_DIR, BITBUCKETNAME);
	if (!config.system->logstyle)
		config.system->logstyle = log_combined;
	config.system->allowusers = true;
	if (!config.system->userid)
	{
		const struct passwd	*pwd = getpwnam(HTTPD_USERID);

		if (!pwd)
			errx(1, "Invalid username: %s", HTTPD_USERID);
		config.system->userid = pwd->pw_uid;
	}
	if (!config.system->groupid &&
		!(config.system->groupid = strtoul(HTTPD_GROUPID, NULL, 10)))
	{
		const struct group	*grp = getgrnam(HTTPD_GROUPID);

		if (!grp)
			errx(1, "Invalid groupname: %s", HTTPD_GROUPID);
		config.system->groupid = grp->gr_gid;
	}
	if (!config.system->indexfiles)
	{
		int		i;
		const size_t	sz = sizeof(defaultindexfiles) / sizeof(char *);

		MALLOC(config.system->indexfiles, char *, sz);
		for (i = 0; defaultindexfiles[i]; i++)
			STRDUP(config.system->indexfiles[i],
				defaultindexfiles[i]);
		config.system->indexfiles[i] = NULL;
	}
	if (!config.system->uidscripts)
	{
		int		i;
		const size_t	sz = sizeof(defaultindexfiles) / sizeof(char *);

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
		if (!current->htmldir && !current->redirfile)
			errx(1, "virtual block must contain htmldir or redirfile");
		if (!current->execdir)
			STRDUP(current->execdir, CGI_DIR);
		if (!current->phexecdir)
			current->phexecdir = checkpath("PhExecDir", SHDATA_DIR, PHEXEC_DIR);
		if (!current->icondir)
			STRDUP(current->icondir, ICON_DIR);
		if (!current->phicondir)
			current->phicondir = checkpath("PhIconDir", SHDATA_DIR, PHICON_DIR);
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
module_config(void)
{
	/* Reset module configurations */
	for (struct module *mod, **mods = modules; (mod = *mods); mods++)
		if (mod->config_general)
			mod->config_general(NULL, NULL);

	for (struct config_option *option = global_options;
			option; option = option->next)
		for (struct module *mod, **mods = modules;
				(mod = *mods); mods++)
			if (mod->config_general)
				mod->config_general(option->key, option->value);

	for (struct config_option *option = unknown_options;
			option; option = option->next)
	{
		/* Check modules for configuration directives */
		bool	used = false;

		for (struct module *mod, **mods = modules;
				(mod = *mods); mods++)
		{
			if (mod->config_general)
				used |= mod->config_general
					(option->key, option->value);
		}
		if (!used)
			errx(1, "illegal global directive: '%s'", option->key);
	}
}

void
remove_config(void)
{
	/* XXX: Rewrite this to avoid memory leaks */
	memset(&config, 0, sizeof config);
	unknown_options = NULL;
}

