/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* Based on xs-httpd/2.3 */
#include	<sys/types.h>

#define		SERVER_IDENT	"xs-httpd/3.0 beta/0.8"

#define		SENDBUFSIZE	8192
#define		MYBUFSIZ	1024
#define		HEADSIZE	8192

#define		ERR_NONE	0
#define		ERR_CONT	1
#define		ERR_QUIT	2

#define		READCHAR	0
#define		READBLOCK	1

#define		MINBYTESPERSEC	32

#ifndef 	S_ISREG
#define		S_ISREG(m)      (((m)&(S_IFMT)) == (S_IFREG))
#endif

extern	char	remotehost[], orig[], dateformat[], rootdir[], currenttime[],
		version[], netbuf[], thishostname[], real_path[], total[],
		name[], port[];
extern	FILE	*access_log, *refer_log;
extern	time_t	modtime;
extern	int		headers, localmode, netbufind, netbufsiz, readlinemode,
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

#ifdef		HANDLE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
extern	int do_ssl;
extern	SSL_CTX *ssl_ctx;
extern	SSL *ssl;
#endif		/* HANDLE_SSL */
/* Wrapper functions are used even if SSL is not enabled */
extern	size_t secread(int, void *, size_t);
extern	size_t secwrite(int, void *, size_t);
extern	size_t secfwrite(void *, size_t, size_t, FILE *);
extern	size_t secprintf(const char *format, ...);
extern	size_t secfputs(char *, FILE *);
