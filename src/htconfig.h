struct virtual {
	char *		hostname;
	char *		htmldir;
	char *		execdir;
	char *		logaccess;
	char *		logerror;
	char *		logreferer;
	struct virtual *	next;
};

struct configuration {
	char *		systemroot;
	char *		address;
	char *		port;
	int		instances;
	char *		pidfile;
	char *		userid;
	char *		groupid;
	unsigned	execasuser: 1;
	unsigned	usessl: 1;
	unsigned	padding: 6;
	struct virtual *	system;
	struct virtual *	users;
	struct virtual *	virtual;
} config;
