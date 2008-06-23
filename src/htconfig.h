/* Copyright (C) 2007-2008 by Johan van Selst */

#ifndef		HTCONFIG_H
#define		HTCONFIG_H

#include	"config.h"
#include	<sys/types.h>
#include	<stdbool.h>
#include	<sys/socket.h>
#include	<pwd.h>

#ifdef		HAVE_PCRE
#include	<pcre.h>
#endif		/* HAVE_PCRE */
#include	"ssl.h"

typedef	enum { log_none, log_traditional, log_combined, log_virtual }	logstyle_t;
typedef enum { auth_none, auth_optional, auth_strict }	sslauth_t;
typedef enum { ERR_NONE, ERR_CONT, ERR_QUIT, ERR_LINE, ERR_CLOSE } xs_error_t;

struct ldap_auth
{
	char	*uri, *attr, *dn, *groups;
	int	version;
};

struct mapping
{
	char	*index, *value;
};
struct maplist
{
	size_t		size;
	struct mapping	*elements;
};

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
	logstyle_t	logstyle;
	struct virtual *	next;
} *current;

struct socket_config
{
	char *		socketname;
	char *		address;
	char *		port;
	sa_family_t	family;
	sslauth_t	sslauth;
	bool		usessl;
	unsigned int	instances;
	char *		sslcertificate;
	char *		sslprivatekey;
	char *		sslcafile;
	char *		sslcapath;
	char *		sslmatchsdn;
	char *		sslmatchidn;
#ifdef		HAVE_PCRE
	pcre *		sslpcresdn;
	pcre *		sslpcreidn;
#endif		/* HAVE_PCRE */
#ifdef		HANDLE_SSL
	SSL_CTX		*ssl_ctx;	/* per socket */
	SSL		*ssl;		/* per instance */
#endif		/* HANDLE_SSL */
	struct socket_config *	next;
} *cursock;

extern struct configuration
{
	char *		systemroot;
	char *		pidfile;
	unsigned int	instances;
	int		priority;
	int		scriptpriority;
	unsigned int	scriptcpulimit;
	unsigned int	scripttimeout;
	bool		execasuser;
	bool		usevirtualuid;
	bool		uselocalscript;
	bool		usednslookup;
	bool		usestricthostname;
	bool		useacceptfilter;
	bool		usessi;
	bool		usecoredump;
	bool		useetag;
	bool		usecontentmd5;
	bool		useput;
	char *		virtualhostdir;
	char *		defaultcharset;
	char *		scriptpath;
	char *		perlscript;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
	struct socket_config *	sockets;
} config;

extern struct session
{
	char		dateformat[512];
	unsigned int	httpversion;	/* 9, 10, 11 */
	unsigned int	rstatus;	/* 200, 301, .. */
	bool		headers;
	bool		headonly;
	bool		postonly;
	bool		postread;
	bool		chunked;
	bool		persistent;
	bool		trailers;
} session;

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
