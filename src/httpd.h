/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* Based on xs-httpd/2.3 */
#include	<sys/types.h>

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

extern	char	remotehost[], dateformat[], currentdir[],
		currenttime[], version[], real_path[],
		name[];
extern	time_t	modtime;
extern	int		headers, netbufind, netbufsiz, readlinemode,
		headonly, postonly;
extern	gid_t	origegid;
extern	uid_t	origeuid;

#ifndef		NOFORWARDS
extern	void	stdheaders		(int, int, int);
extern	void	alarm_handler		(int);
extern	void	error			(const char *);
extern	void	redirect		(const char *, int);
extern	int	readline		(int, char *);
extern	void	server_error		(const char *, const char *);
extern	void	logrequest		(const char *, long);
extern	int	check_auth		(FILE *);
extern	void	setcurrenttime		(void);
#endif		/* NOFORWARDS */

#ifdef		HANDLE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
extern	SSL_CTX *ssl_ctx;
#endif		/* HANDLE_SSL */
/* Wrapper functions are used even if SSL is not enabled */
extern	int	secread(int, void *, size_t);
extern	int	secwrite(int, void *, size_t);
extern	int	secfwrite(void *, size_t, size_t, FILE *);
extern	int	secprintf(const char *format, ...);
extern	int	secfputs(char *, FILE *);
