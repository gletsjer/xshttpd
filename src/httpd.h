/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* Based on xs-httpd/2.3 */

#define		SERVER_IDENT	"xs-httpd/3.0 beta/0.2"

#define		SENDBUFSIZE	8192
#define		MYBUFSIZ	1024

#define		ERR_NONE	0
#define		ERR_CONT	1
#define		ERR_QUIT	2

#define		MINBYTESPERSEC	32

#ifndef 	S_ISREG
#define		S_ISREG(m)      (((m)&(S_IFMT)) == (S_IFREG))
#endif

extern	char	remotehost[], orig[], dateformat[], rootdir[], currenttime[],
		version[], netbuf[], thishostname[], real_path[], total[],
		name[];
extern	FILE	*access_log, *refer_log;
extern	time_t	modtime;
extern	int	port, headers, localmode, netbufind, netbufsiz, readlinemode,
		headonly, postonly;
extern	gid_t	group_id, origegid;
extern	uid_t	user_id, origeuid;

#ifndef		NOFORWARDS
extern	VOID	stdheaders		PROTO((int, int, int));
extern	VOID	alarm_handler		PROTO((int));
extern	VOID	error			PROTO((const char *));
extern	VOID	redirect		PROTO((const char *, int));
extern	int	readline		PROTO((int, char *));
extern	VOID	server_error		PROTO((const char *, const char *));
extern	VOID	error			PROTO((const char *));
extern	char	*escape			PROTO((const char *));
extern	int	check_auth		PROTO((FILE *));
extern	VOID	setcurrenttime		PROTO((void));
#endif		/* NOFORWARDS */
