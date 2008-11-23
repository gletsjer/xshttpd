#ifndef		MD5_H
#define		MD5_H

#ifdef		HAVE_MD5

#ifdef		USE_OPENSSL_MD5
# include	<openssl/md5.h>
#endif		/* Not USE_OPENSSL_MD5 */
#ifdef		HAVE_LIBMD
# include	<md5.h>
#endif		/* HAVE_LIBMD */

#ifndef		MD5_DIGEST_LENGTH
# define	MD5_DIGEST_LENGTH		16
#endif		/* MD5_DIGEST_LENGTH */
#ifndef		MD5_DIGEST_STRING_LENGTH
# define	MD5_DIGEST_STRING_LENGTH	(2 * MD5_DIGEST_LENGTH + 1)
#endif		/* MD5_DIGEST_STRING_LENGTH */
#ifndef		MD5_DIGEST_B64_LENGTH
# define	MD5_DIGEST_B64_LENGTH		((4 * MD5_DIGEST_LENGTH + 2) / 3 + 1)
#endif		/* MD5_DIGEST_B64_LENGTH */

#ifdef		USE_OPENSSL_MD5
# ifndef	HAVE_MD5DATA
char *	MD5Data		(const unsigned char *, size_t, char *);
# endif		/* HAVE_MD5DATA */
#endif		/* USE_OPENSSL_MD5 */

#endif		/* HAVE_MD5 */

#endif		/* MD5_H */
