/* Copyright (C) 2007-2008 by Johan van Selst */

#ifndef		SSL_H
#define		SSL_H

#include	"config.h"
#include	<stdio.h>
#include	<stdbool.h>

#include	<openssl/ssl.h>
#include	<openssl/tls1.h>
#ifdef		TLSEXT_NAMETYPE_host_name
# ifndef	OPENSSL_NO_TLSEXT
#  define	HANDLE_SSL_TLSEXT
# endif		/* OPENSSL_NO_TLSEXT */
#endif		/* TLSEXT_NAMETYPE_host_name */

/* forward declaration, defined in htconfig.h */
struct	mapping;
struct	maplist;
struct	socket_config;
struct	ssl_vhost;

/* Wrapper functions are used even if SSL is not enabled */
bool	initssl(void);
void	ssl_environment(void);
void	loadssl(struct socket_config *, struct ssl_vhost *);
void	endssl(void);

void	initreadmode(bool);
ssize_t	secread(int, void *, size_t) NONNULL;
size_t	secfread(void *, size_t, size_t, FILE *) NONNULL;
ssize_t	readheaders(int, struct maplist);

ssize_t	secwrite(const char *, size_t);
size_t	secfwrite(const char *, size_t, size_t, FILE *);
ssize_t	secputs(const char *);
ssize_t	secprintf(const char *format, ...) PRINTF_LIKE(1, 2);

#endif		/* SSL_H */
