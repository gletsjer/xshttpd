/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HTTPD_H
#define		HTTPD_H

/* Based on xs-httpd/2.3 */
#include	"config.h"
#include	<sys/types.h>
#include	<stdbool.h>
#include	<sys/stat.h>

#define		RWBUFSIZE	4096
#define		MYBUFSIZ	1024
#define		LINEBUFSIZE	4096
#define		HEADSIZE	10240

#define		ERR_NONE	0
#define		ERR_CONT	1
#define		ERR_QUIT	2
#define		ERR_LINE	3
#define		ERR_CLOSE	4

#define		MINBYTESPERSEC	32

#ifndef 	S_ISREG
#define		S_ISREG(m)      (((m)&(S_IFMT)) == (S_IFREG))
#endif		/* S_ISREG */

extern	char	remotehost[], dateformat[], currentdir[],
		currenttime[], httpver[], real_path[],
		orig_filename[];
extern	int		headers, rstatus;
extern	bool		headonly, postonly, postread, chunked, persistent, trailers;
extern	gid_t	origegid;
extern	uid_t	origeuid;

void	stdheaders		(bool, bool, bool);
void	alarm_handler		(int);
void	xserror			(int, const char *, ...) PRINTF_LIKE(2, 3);
void	redirect		(const char *, bool, bool) NONNULL;
int	readline		(int, char *, size_t) NONNULL WARNUNUSED;
void	server_error		(int, const char *, const char *) NONNULL;
void	logrequest		(const char *, off_t) NONNULL;
void	setcurrenttime		(void);

#endif		/* HTTPD_H */
