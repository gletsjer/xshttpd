/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* Based on xs-httpd/2.3 */
#include	<sys/types.h>

#define		RWBUFSIZE	8192
#define		MYBUFSIZ	1024
#define		LINEBUFSIZE	1024
#define		HEADSIZE	8192

#define		ERR_NONE	0
#define		ERR_CONT	1
#define		ERR_QUIT	2
#define		ERR_LINE	3

#define		READCHAR	0
#define		READBLOCK	1

#define		MINBYTESPERSEC	32

#ifndef 	S_ISREG
#define		S_ISREG(m)      (((m)&(S_IFMT)) == (S_IFREG))
#endif

extern	char	remotehost[], dateformat[], currentdir[],
		currenttime[], version[], real_path[],
		orig_filename[];
extern	time_t	modtime;
extern	int		headers, headonly, postonly, chunked;
extern	gid_t	origegid;
extern	uid_t	origeuid;

void	stdheaders		(int, int, int);
void	alarm_handler		(int);
void	error			(const char *);
void	redirect		(const char *, int);
int	readline		(int, char *, size_t);
void	server_error		(const char *, const char *);
void	logrequest		(const char *, long);
int	check_auth		(FILE *);
void	setcurrenttime		(void);

