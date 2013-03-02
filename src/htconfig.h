/* Copyright (C) 2007-2008 by Johan van Selst */

#ifndef		HTCONFIG_H
#define		HTCONFIG_H

#include	"config.h"
#include	<sys/types.h>
#include	<stdbool.h>
#include	<sys/socket.h>
#include	<sys/stat.h>
#include	<pwd.h>

#ifdef		HAVE_PCRE
#include	<pcre.h>
#endif		/* HAVE_PCRE */
#include	"ssl.h"
#include	"httypes.h"

/* Virtual configuration structure
 * contains all values specific to a vhost entry in the configuration
 */
extern struct virtual
{
	char *		hostname;
	char *		htmldir;
	char *		execdir;
	char *		phexecdir;
	char *		icondir;
	char *		phicondir;
	char *		logaccess;
	char *		logerror;
	char *		logreferer;
	char *		logscript;
	char *		thisdomain;
	char *		redirfile;
	char *		fcgipath;
	char *		fcgisocket;
	void *		fcgiserver;
	unsigned int	phpfcgichildren;
	unsigned int	phpfcgirequests;
	char **		indexfiles;
	char **		aliases;
	char **		uidscripts;
	char *		socketname;
	uid_t		userid;
	gid_t		groupid;
	FILE *		openaccess;
	FILE *		openreferer;
	FILE *		openerror;
	FILE *		openscript;
	xs_logstyle_t	logstyle;
	bool		allowusers;
	char *		sslcertificate;
	char *		sslprivatekey;
	bool		usests;
	bool		stssubdomains;
	unsigned int	stsmaxage;
	struct virtual *	next;
} *current;

/* SSL configuration structure
 * contains all values specific to a ssl entry in the socket configuration
 */
struct ssl_vhost
{
	struct virtual *	virtual;
	SSL_CTX *		ssl_ctx;
	struct ssl_vhost *	next;
};

/* Socket configuration structure
 * contains all values specific to a socket entry in the configuration
 */
struct socket_config
{
	char *		socketname;
	char *		address;
	char *		port;
	sa_family_t	family;
	xs_sslauth_t	sslauth;
	bool		usessl;
	unsigned int	instances;
	char *		sslcertificate;
	char *		sslprivatekey;
	char *		sslcafile;
	char *		sslcapath;
	char *		sslcrlfile;
	char *		sslcrlpath;
	char *		sslcalist;
	char *		sslmatchsdn;
	char *		sslmatchidn;
	char *		sslcipherlist;
#define		USE_SESSIONS	1
#ifdef		USE_SESSIONS
	char *		session_file;
	char *		session_lock;
#endif		/* USE_SESSIONS */
#ifdef		HAVE_PCRE
	pcre *		sslpcresdn;
	pcre *		sslpcreidn;
#endif		/* HAVE_PCRE */
	struct ssl_vhost *	sslvhosts;
	SSL_CTX *	ssl_ctx;	/* per socket */
	SSL *		ssl;		/* per instance */
	struct socket_config *	next;
} *cursock;

/* Global configuration structure
 * contains all global configuration options
 */
extern struct configuration
{
	char *		pidfile;
	unsigned int	instances;
	int		priority;
	int		scriptpriority;
	unsigned int	scriptcpulimit;
	unsigned int	scripttimeout;
	unsigned int	dnstimeout;
	unsigned int	dnsattempts;
	bool		execasuser;
	bool		usevirtualuid;
	bool		uselocalscript;
	bool		usescriptargs;
	bool		usednslookup;
	bool		usestricthostname;
	bool		useacceptfilter;
	bool		usessi;
	bool		usecoredump;
	bool		usesendfile;
	bool		useetag;
	bool		usecontentmd5;
	bool		useput;
	bool		usetrace;
	bool		usesslsessionstore;
	char *		virtualhostdir;
	char *		defaultcharset;
	char *		scriptpath;
	char *		scriptumask;
	char *		serverident;
	char *		proxyident;
	char **		modules;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
	struct socket_config *	sockets;
} config;

/* Session structure
 * contains global values that are specific
 * for the current request/response session
 */
extern struct session
{
	char		dateformat[512];
	unsigned int	httpversion;	/* 9, 10, 11 */
	unsigned int	rstatus;	/* 200, 301, .. */
	off_t		size;
	off_t		offset;
	off_t		bytes;
	time_t		modtime;
	const char *	etag;		/* not malloced */
	bool		headers;
	bool		headonly;
	bool		postonly;
	bool		postread;
	bool		chunked;
	bool		persistent;
	bool		trailers;
	bool		via;
	struct maplist	request_headers;
	struct maplist	response_headers;
} session;

/* Environment structure
 * contains global values that refer directly
 * to corresponding environment variables (getenv)
 */
extern struct env
{
	const char *	authorization;
	const char *	path_info;
	const char *	query_string;
	const char *	remote_addr;
	const char *	remote_host;
	const char *	request_method;
	const char *	request_uri;
	const char *	server_protocol;
	off_t		content_length;
} env;

#endif		/* HTCONFIG_H */
