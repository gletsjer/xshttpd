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
	struct virtual *	next;
};

struct configuration {
	char *		systemroot;
	char *		address;
	char *		port;
	int		instances;
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
