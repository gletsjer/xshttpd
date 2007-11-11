/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		METHODS_H
#define		METHODS_H

#include	"config.h"
#ifdef		HAVE_LIBMD
# include	<md5.h>
extern	MD5_CTX	*md5context;
#endif		/* HAVE_MD5 */

void	loadcompresstypes	(void);
void	loadscripttypes		(char *, char *);
void	loadfiletypes		(char *, char *);

void	do_get			(char *);
void	do_post			(char *);
void	do_head			(char *);
void	do_put			(char *);
void	do_delete		(char *);
void	do_options		(const char *);
void	do_trace		(const char *);
void	do_proxy		(const char *, const char *);

#endif		/* METHODS_H */
