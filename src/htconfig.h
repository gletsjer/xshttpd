/* Copyright (C) 2007 by Johan van Selst */

#ifndef		HTCONFIG_H
#define		HTCONFIG_H

#include	"config.h"
#include	<sys/types.h>
#include	<sys/socket.h>
#include	<pwd.h>

#ifdef		HAVE_PCRE
#include	<pcre.h>
#endif		/* HAVE_PCRE */
#include	"ssl.h"

typedef	enum { log_none, log_traditional, log_combined, log_virtual }	logstyle_t;
typedef enum { auth_none, auth_optional, auth_strict }	sslauth_t;

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
	char *		logaccess;
	char *		logerror;
	char *		logreferer;
	char *		logscript;
	char *		thisdomain;
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
	unsigned	usessl: 1;
	int		instances;
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
	int		instances;
	int		priority;
	int		scriptpriority;
	unsigned int	scriptcpulimit;
	unsigned int	scripttimeout;
	unsigned	execasuser: 1;
	unsigned	usevirtualuid: 1;
	unsigned	uselocalscript: 1;
	unsigned	usednslookup: 1;
	unsigned	usestricthostname: 1;
	unsigned	useacceptfilter: 1;
	unsigned	usessi: 1;
	unsigned	usecoredump: 1;
	unsigned	useetag: 1;
	unsigned	usecontentmd5: 1;
	unsigned	useput: 1;
	char *		virtualhostdir;
	char *		defaultcharset;
	char *		scriptpath;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
	struct socket_config *	sockets;
} config;

#endif		/* HTCONFIG_H */
