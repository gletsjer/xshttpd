/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2015 by Johan van Selst (johans@stack.nl) */

#ifndef		ALTERNATIVE_H
#define		ALTERNATIVE_H

#include	"config.h"

#include	<inttypes.h>
#include	<stdarg.h>
#include	<stdint.h>
#include	<stdio.h>
#ifdef		HAVE_TIME_H
# include	<time.h>
#endif		/* HAVE_TIME_H */
#include	<limits.h>
#include	<sys/socket.h>
#include	<sys/stat.h>
#include	<arpa/inet.h>

/***** External variables *****/

#if		!HAVE_DECL_ENVIRON
extern	char	**environ;
#endif		/* HAVE_DECL_ENVIRON */

#if		!HAVE_DECL_OPTARG
extern	char	*optarg;
extern	int	optind;
#endif	/* HAVE_DECL_OPTARG */

#if		!HAVE_DECL_SYS_ERRLIST
extern	char		*sys_errlist[];
extern	const int	sys_nerr;
#endif		/* HAVE_DECL_SYS_ERRLIST */

/***** Common types *****/

#ifndef		HAVE_SOCKLEN_T
typedef	size_t		socklen_t;
#endif		/* HAVE_SOCKLEN_T */

#ifndef		HAVE_SA_FAMILY_T
typedef unsigned char	sa_family_t;
#endif		/* HAVE_SA_FAMILY_T */

#ifndef		HAVE_IN_ADDR_T
typedef uint32_t	in_addr_t;
#endif		/* HAVE_IN_ADDR_T */

#ifndef		HAVE_IN_PORT_T
typedef uint16_t	in_port_t;
#endif		/* HAVE_IN_PORT_T */

/***** Useful defines *****/

#ifndef		S_ISREG
# define	S_ISREG(m)	(((m)&(S_IFMT)) == (S_IFREG))
#endif		/* S_ISREG */

#ifdef		NULL
# undef		NULL
#endif		/* NULL */
#define		NULL		((void *)0)

/***** Libcompat functions *****/

#ifndef		HAVE_CLOSEFROM
int	closefrom	(int);
#endif		/* HAVE_CLOSEFROM */

#ifndef		HAVE_ERR
void	err		(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	errx		(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	warn		(const char *, ...) PRINTF_LIKE(1, 2);
void	warnx		(const char *, ...) PRINTF_LIKE(1, 2);
#endif		/* HAVE_ERR */

#ifndef		HAVE_FNMATCH
int	fnmatch		(const char *, const char *, int);
#endif		/* HAVE_FNMATCH */

#ifndef		HAVE_INET_ATON
int	inet_aton	(const char *, struct in_addr *);
#endif		/* HAVE_INET_ATON */

#ifndef		HAVE_KILLPG
int	killpg		(pid_t, int);
#endif		/* HAVE_KILLPG */

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
void	initproctitle	(int, char **, char **);
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

#ifndef		HAVE_STRNDUP
char *	strndup		(const char *str, size_t n);
#endif		/* HAVE_STRNDUP */

#ifndef		HAVE_STRERROR
const char *	strerror	(int code);
#endif		/* HAVE_STRERROR */

#ifndef		HAVE_SRANDOMDEV
void	srandomdev	(void);
#endif		/* HAVE_SRANDOMDEV */

#ifndef		HAVE_FGETLN
char *	fgetln		(FILE *, size_t *);
#endif		/* HAVE_FGETLN */

#ifndef		HAVE_FPARSELN
char *	fparseln	(FILE *, size_t *, size_t *, const char[3], int);
# define FPARSELN_UNESCESC       0x01
# define FPARSELN_UNESCCONT      0x02
# define FPARSELN_UNESCCOMM      0x04
# define FPARSELN_UNESCREST      0x08
# define FPARSELN_UNESCALL       0x0f
#endif		/* HAVE_FPARSELN */

#endif		/* ALTERNATIVE_H */
