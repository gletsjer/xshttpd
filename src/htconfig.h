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
	FILE *		openaccess;
	FILE *		openreferer;
	enum	{ none, traditional, combined }		logstyle;
	unsigned	virtualid: 1;
	unsigned	padding: 7;
	struct virtual *	next;
} *current;

extern struct configuration {
	char *		systemroot;
	char *		address;
	char *		port;
	int			family;
	unsigned short	instances;
	unsigned short	localmode;
	char *		pidfile;
	uid_t		userid;
	gid_t 		groupid;
	unsigned	execasuser: 1;
	unsigned	usecharset: 1;
	unsigned	usessl: 1;
	unsigned	userestrictaddr: 1;
	unsigned	usevirtualhost: 1;
	unsigned	usevirtualuid: 1;
	unsigned	uselocalscript: 1;
	unsigned	padding: 1;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
} config;
