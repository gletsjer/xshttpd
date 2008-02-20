/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */

#ifndef		ALTERNATIVE_H
#define		ALTERNATIVE_H

#include	"config.h"

#include	<inttypes.h>
#include	<stdarg.h>
#ifdef		HAVE_TIME_H
#include	<time.h>
#endif		/* HAVE_TIME_H */
#include	<sys/socket.h>
#include	<sys/stat.h>
#include	<arpa/inet.h>

#if		!HAVE_DECL_ENVIRON
extern	char	**environ;
#endif		/* HAVE_DECL_ENVIRON */

#if		!HAVE_DECL_OPTARG
extern	char	*optarg;
extern	int	optind;
#endif          /* HAVE_DECL_OPTARG */

#ifndef             HAVE_DECL_SYS_ERRLIST
extern	char		*sys_errlist[];
extern	const int	sys_nerr;
#endif          /* HAVE_DECL_SYS_ERRLIST */

#ifndef		HAVE_SOCKLEN_T
typedef	size_t		socklen_t;
#endif		/* HAVE_SOCKLEN_T */
#ifndef		HAVE_SA_FAMILY_T
typedef unsigned char	sa_family_t;
#endif		/* HAVE_SA_FAMILY_T */

#ifndef		S_ISREG
#define		S_ISREG(m)	(((m)&(S_IFMT)) == (S_IFREG))
#endif		/* S_ISREG */

#ifndef		HAVE_CLOSEFROM
int	closefrom	(int);
#endif		/* HAVE_CLOSEFROM */

#ifndef		HAVE_CRYPT
char *	crypt		(const char *, const char *);
#endif		/* HAVE_CRYPT */

#ifndef		HAVE_ERR
void	err		(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	errx		(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	warn		(const char *, ...) PRINTF_LIKE(1, 2);
void	warnx		(const char *, ...) PRINTF_LIKE(1, 2);
#endif		/* HAVE_ERR */

#ifndef		HAVE_INET_ATON
int	inet_aton	(const char *, struct in_addr *);
#endif		/* HAVE_INET_ATON */

#ifndef		HAVE_KILLPG
int	killpg		(pid_t, int);
#endif		/* HAVE_KILLPG */

#ifdef		USE_OPENSSL_MD5
# ifndef	HAVE_MD5DATA
char *	MD5Data		(const unsigned char *, size_t, char *);
# endif		/* HAVE_MD5DATA */
#endif		/* USE_OPENSSL_MD5 */

#ifndef		HAVE_MEMMEM
void *	memmem		(const void *, size_t, const void *, size_t);
#endif		/* HAVE_MEMMEM */

#ifndef		MKSTEMP
int	mkstemp		(char *);
#endif		/* MKSTEMP */

#ifndef		HAVE_SETEUID
int	seteuid		(uid_t);
#endif		/* HAVE_SETEUID */
#ifndef		HAVE_SETEGID
int	setguid		(gid_t);
#endif		/* HAVE_SETEGID */

#ifndef		HAVE_SETGROUPS
int	setgroups	(int ngroups, const gid_t *gidset);
#endif		/* HAVE_SETGROUPS */

#ifndef		HAVE_SETPROCTITLE
void	setproctitle	(const char *, ...) PRINTF_LIKE(1, 2);
void	initproctitle	(int, char **);
#endif		/* HAVE_SETPROCTITLE */

#ifndef		HAVE_ASPRINTF
int	asprintf	(char **, const char *, ...) PRINTF_LIKE(2, 3);
#endif		/* HAVE_ASPRINTF */

#ifndef		HAVE_STRCASESTR
char *	strcasestr	(const char *, const char *);
#endif		/* HAVE_STRCASESTR */

#ifndef		HAVE_STRLCAT
size_t	strlcat		(char *, const char *, size_t);
#endif		/* HAVE_STRLCAT */

#ifndef		HAVE_STRLCPY
size_t	strlcpy		(char *, const char *, size_t);
#endif		/* HAVE_STRLCPY */

#ifndef		HAVE_STRPTIME
char *	strptime	(const char *, const char *, struct tm *);
#endif		/* HAVE_STRPTIME */

#ifndef		HAVE_STRSEP
char *	strsep		(char **, const char *);
#endif		/* HAVE_STRSEP */

#ifndef		HAVE_SRANDOMDEV
void	srandomdev	(void);
#endif		/* HAVE_SRANDOMDEV */

#endif		/* ALTERNATIVE_H */
