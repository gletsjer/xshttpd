/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HTTPD_H
#define		HTTPD_H

/* Based on xs-httpd/2.3 */
#include	"config.h"
#include	"httypes.h"
#include	<sys/types.h>
#include	<stdbool.h>

extern	char	currenttime[];
extern	gid_t	origegid;
extern	uid_t	origeuid;

void	stdheaders		(bool, bool, bool);
void	maplist_stdheaders	(struct maplist *, bool, bool);
void	alarm_handler		(int);
void	xserror			(int, const char *, ...) PRINTF_LIKE(2, 3);
void	redirect		(const char *, bool, bool) NONNULL;
xs_error_t	readline	(int, char *, size_t) NONNULL WARNUNUSED;
void	server_error		(int, const char *, const char *) NONNULL;
void	logrequest		(const char *, off_t) NONNULL;

#endif		/* HTTPD_H */
