/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: alternative.h,v 1.6 2007/04/07 21:34:50 johans Exp $ */

#ifndef		ALTERNATIVE_H
#define		ALTERNATIVE_H	1

#include	"config.h"

#include	<sys/types.h>
#include	<inttypes.h>
#include	<stdarg.h>
#ifdef		HAVE_TIME_H
#include	<time.h>
#endif		/* HAVE_TIME_H */

#if		!HAVE_DECL_ENVIRON
extern	char	**environ;
#endif		/* HAVE_DECL_ENVIRON */

#if		!HAVE_DECL_OPTARG
extern	char	*optarg;
extern	int	optind;
#endif          /* HAVE_DECL_OPTARG */


#ifndef		HAVE_STRERROR
extern	const char *	strerror		(int);
#endif		/* HAVE_STRERROR */

#ifndef             HAVE_DECL_SYS_ERRLIST
extern	char		*sys_errlist[];
extern	const int	sys_nerr;
#endif          /* HAVE_DECL_SYS_ERRLIST */

#ifndef		HAVE_SOCKLEN_T
typedef	size_t	socklen_t;
#endif		/* HAVE_SOCKLEN_T */

#ifndef		HAVE_ERR
void	err		(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	errx		(int, const char *, ...) PRINTF_LIKE(2, 3) NORETURN;
void	warn		(const char *, ...) PRINTF_LIKE(1, 2);
void	warnx		(const char *, ...) PRINTF_LIKE(1, 2);
#endif		/* HAVE_ERR */

#ifndef		HAVE_KILLPG
int	killpg		(pid_t, int);
#endif		/* HAVE_KILLPG */

#ifdef		USE_OPENSSL_MD5
# ifndef	HAVE_MD5DATA
char *	MD5Data		(const unsigned char *, unsigned int, char *);
# endif		/* HAVE_MD5DATA */
#endif		/* USE_OPENSSL_MD5 */

#ifndef		HAVE_MEMMEM
void *	memmem		(const void *, size_t, const void *, size_t);
#endif		/* HAVE_MEMMEM */

#ifndef		HAVE_SETENV
char	*getenv		(const char *);
int	setenv		(const char *, const char *, int);
void	unsetenv	(const char *);
#endif		/* HAVE_SETENV */

#ifndef		HAVE_SETGROUPS
int	setgroups	(int ngroups, const gid_t *gidset);
#endif		/* HAVE_SETGROUPS */

#ifndef		HAVE_SETPROCTITLE
void	setproctitle	(const char *, ...) PRINTF_LIKE(1, 2);
void	initproctitle	(int, char **);
#endif		/* HAVE_SETPROCTITLE */

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

#ifndef 	HAVE_SNPRINTF
int	snprintf	(char *, size_t, const char *, ...) PRINTF_LIKE(3, 4);
int	vsnprintf	(char *, size_t, const char *, va_list);
#endif		/* HAVE_VSNPRINTF */

#ifndef		HAVE_SETEUID
# ifdef		HAVE_SETRESUID
#  define	seteuid(a)	setresuid(-1, (a), -1)
# else		/* Not HAVE_SETRESUID */
#  define	seteuid(a)	setreuid(-1, (a))
# endif		/* HAVE_SETRESUID */
#endif		/* HAVE_SETEUID */

#ifndef		HAVE_SETEGID
# ifdef		HAVE_SETRESGID
#  define	setegid(a)	setresgid(-1, (a), -1)
# else		/* Not HAVE_SETRESGID */
#  define	setegid(a)	setregid(-1, (a))
# endif		/* HAVE_SETRESGID */
#endif		/* HAVE_SETEGID */

#ifndef		PRId64
#define		PRId64		"llu"
#endif		/* PRId64 */

#endif		/* ALTERNATIVE_H */
