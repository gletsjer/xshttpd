#include <sys/types.h>
#include <pwd.h>

struct virtual {
	char *		hostname;
	char *		htmldir;
	char *		execdir;
	char *		phexecdir;
	char *		logaccess;
	char *		logerror;
	char *		logreferer;
	enum	{ none, traditional, combined }		logstyle;
	unsigned	virtualid: 1;
	unsigned	padding: 7;
	struct virtual *	next;
} *current;

struct configuration {
	char *		systemroot;
	char *		address;
	char *		port;
	unsigned short	instances;
	unsigned short	localmode;
	char *		pidfile;
	uid_t		userid;
	gid_t 		groupid;
	unsigned	execasuser: 1;
	unsigned	usessl: 1;
	unsigned	padding: 6;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
} config;
