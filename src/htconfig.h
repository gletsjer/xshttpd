#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>

#ifdef		HANDLE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif		/* HANDLE_SSL */
#ifdef		HAVE_PCRE
#include <pcre.h>
#endif		/* HAVE_PCRE */

typedef	enum { log_none, log_traditional, log_combined, log_virtual }	logstyle_t;
typedef enum { auth_none, auth_optional, auth_strict }	sslauth_t;

extern struct virtual {
	char *		hostname;
	char *		htmldir;
	char *		execdir;
	char *		phexecdir;
	char *		logaccess;
	char *		logerror;
	char *		logreferer;
	char **		indexfiles;
	char **		aliases;
	uid_t		userid;
	gid_t		groupid;
	FILE *		openaccess;
	FILE *		openreferer;
	FILE *		openerror;
	logstyle_t	logstyle;
	unsigned	virtualid: 1;
	unsigned	padding: 7;
	struct virtual *	next;
} *current;

struct socket_config {
	char *		address;
	char *		port;
	sa_family_t	family;
	unsigned short	instances;
	unsigned	usessl: 1;
	unsigned	padding: 7;
	char *		sslcertificate;
	char *		sslprivatekey;
	sslauth_t	sslauth;
	char *		sslcafile;
	char *		sslcapath;
#ifdef		HAVE_PCRE
	char *		sslmatchsdn;
	char *		sslmatchidn;
	pcre *		sslpcresdn;
	pcre *		sslpcreidn;
#endif		/* HAVE_PCRE */
#ifdef		HANDLE_SSL
	SSL		*ssl;
#endif		/* HANDLE_SSL */
	struct socket_config *	next;
} *cursock;

extern struct configuration {
	char *		systemroot;
	int		num_sockets;
	unsigned short	instances;
	unsigned short	localmode;
	int		priority;
	char *		pidfile;
	int		scriptpriority;
	unsigned int	scriptcpulimit;
	unsigned int	scripttimeout;
	char *		scriptpath;
	unsigned	execasuser: 1;
	unsigned	usecharset: 1;
	unsigned	userestrictaddr: 1;
	unsigned	usevirtualhost: 1;
	unsigned	usevirtualuid: 1;
	unsigned	uselocalscript: 1;
	unsigned	usecompressed: 1;
	unsigned	usednslookup: 1;
	unsigned	usepcreredir: 1;
	unsigned	useldapauth: 1;
	unsigned	padding: 6;
	char *		sslcertificate;
	char *		sslprivatekey;
	char *		virtualhostdir;
	char *		defaultcharset;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
	struct socket_config *	sockets;
} config;

