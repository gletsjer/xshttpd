/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */

#ifndef		AUTHENTICATE_H
#define		AUTHENTICATE_H

#include	"config.h"
#ifdef		USE_OPENSSL_MD5
# include	<openssl/md5.h>
#else		/* Not USE_OPENSSL_MD5 */
# ifdef		HAVE_MD5
#  include	<md5.h>
# endif		/* HAVE_MD5 */
#endif		/* Not USE_OPENSSL_MD5 */

#include	"ldap.h"

#ifndef		MD5_DIGEST_LENGTH
# define	MD5_DIGEST_LENGTH		16
#endif		/* MD5_DIGEST_LENGTH */
#ifndef		MD5_DIGEST_STRING_LENGTH
# define	MD5_DIGEST_STRING_LENGTH	(2 * MD5_DIGEST_LENGTH + 1)
#endif		/* MD5_DIGEST_STRING_LENGTH */

#define		REALM		"this page"
#define		MAX_NONCE_LENGTH	60

extern char	authentication[];

void	initnonce	(void);
int	check_auth	(const char *, const struct ldap_auth *);

#endif		/* AUTHENTICATE_H */
