#include <sys/types.h>
#include <pwd.h>

extern struct virtual {
	char *		hostname;
	char *		htmldir;
	char *		execdir;
	char *		phexecdir;
	char *		logaccess;
	char *		logerror;
	char *		logreferer;
	uid_t		userid;
	gid_t		groupid;
	FILE *		openaccess;
	FILE *		openreferer;
	FILE *		openerror;
	enum	{ none, traditional, combined }		logstyle;
	unsigned	virtualid: 1;
	unsigned	padding: 7;
	struct virtual *	next;
} *current;

struct socket_config {
	char *		address;
	char *		port;
	int		family;
	unsigned short	instances;
	unsigned	usessl: 1;
	unsigned	padding: 7;
	struct socket_config *	next;
};

extern struct configuration {
	char *		systemroot;
	char *		address;
	char *		port;
	int		family;
	int		num_sockets;
	int		script_timeout;
	unsigned short	instances;
	unsigned short	localmode;
	int		priority;
	int		scriptpriority;
	char *		pidfile;
	unsigned	execasuser: 1;
	unsigned	usecharset: 1;
	unsigned	usessl: 1;
	unsigned	userestrictaddr: 1;
	unsigned	usevirtualhost: 1;
	unsigned	usevirtualuid: 1;
	unsigned	uselocalscript: 1;
	unsigned	usecompressed: 1;
	/* unsigned	padding: 8; */
	char *		sslcertificate;
	char *		sslprivatekey;
	char *		virtualhostdir;
	char *		defaultcharset;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
	struct socket_config *	sockets;
} config;
