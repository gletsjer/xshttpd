#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>

#ifdef		HAVE_PCRE
#include <pcre.h>
#endif		/* HAVE_PCRE */
#include "ssl.h"

typedef	enum { log_none, log_traditional, log_combined, log_virtual }	logstyle_t;
typedef enum { auth_none, auth_optional, auth_strict }	sslauth_t;

struct ldap_auth
{
	char	*uri, *attr, *dn, *groups;
	int	version;
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
	char *		thisdomain;
	char **		indexfiles;
	char **		aliases;
	char *		socketname;
	uid_t		userid;
	gid_t		groupid;
	FILE *		openaccess;
	FILE *		openreferer;
	FILE *		openerror;
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
	SSL		*ssl;
#endif		/* HANDLE_SSL */
	struct socket_config *	next;
} *cursock;

extern struct configuration
{
	char *		systemroot;
	int		instances;
	int		priority;
	char *		pidfile;
	int		scriptpriority;
	unsigned int	scriptcpulimit;
	unsigned int	scripttimeout;
	char *		scriptpath;
	unsigned	execasuser: 1;
	unsigned	usevirtualuid: 1;
	unsigned	uselocalscript: 1;
	unsigned	usednslookup: 1;
	unsigned	useacceptfilter: 1;
	unsigned	usessi: 1;
	char *		virtualhostdir;
	char *		defaultcharset;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
	struct socket_config *	sockets;
} config;

