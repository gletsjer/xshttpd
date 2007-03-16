/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */

#ifdef		HAVE_OPENSSL_MD5
# include	<openssl/md5.h>
#else		/* Not HAVE_OPENSSL_MD5 */
# ifdef		HAVE_MD5
#  include	<md5.h>
# endif		/* HAVE_MD5 */
#endif		/* Not HAVE_OPENSSL_MD5 */

#ifndef		MD5_DIGEST_LENGTH
# define	MD5_DIGEST_LENGTH		16
#endif		/* MD5_DIGEST_LENGTH */
#ifndef		MD5_DIGEST_STRING_LENGTH
# define	MD5_DIGEST_STRING_LENGTH	(2 * MD5_DIGEST_LENGTH + 1)
#endif		/* MD5_DIGEST_STRING_LENGTH */

#define		REALM		"this page"
#define		MAX_NONCE_LENGTH	60

extern char	authentication[MYBUFSIZ];

void	initnonce	(void);
int	check_auth	(FILE *);

