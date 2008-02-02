/* Copyright (C) 2007-2008 by Johan van Selst */

#ifndef		SSL_H
#define		SSL_H

#include	"config.h"
#include	<stdio.h>

#ifdef		HANDLE_SSL
# ifndef	USE_OPENSSL_MD5
#  define	OPENSSL_NO_MD5
#  define	HEADER_MD5_H	/* trick older openssl */
# endif		/* Not USE_OPENSSL_MD5 */
#include	<openssl/ssl.h>
#endif		/* HANDLE_SSL */

#include	"htconfig.h"
/* forward declaration, defined in htconfig.h */
struct	mapping;
struct	maplist;
struct	socket_config;

/* Wrapper functions are used even if SSL is not enabled */
bool	initssl(void);
void	ssl_environment(void);
void	loadssl(struct socket_config *) NONNULL;
void	endssl(void);

void	initreadmode(bool);
ssize_t	secread(int, void *, size_t) NONNULL;
size_t	secfread(void *, size_t, size_t, FILE *) NONNULL;
ssize_t	readheaders(int, struct maplist *) NONNULL;
void	freeheaders(struct maplist *) NONNULL;

ssize_t	secwrite(const char *, size_t);
size_t	secfwrite(const char *, size_t, size_t, FILE *);
ssize_t	secputs(const char *);
ssize_t	secprintf(const char *format, ...) PRINTF_LIKE(1, 2);

#endif		/* SSL_H */
