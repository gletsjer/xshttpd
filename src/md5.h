#ifndef		MD5_H
#define		MD5_H

# include	<openssl/md5.h>

#ifndef		MD5_DIGEST_LENGTH
# define	MD5_DIGEST_LENGTH		16
#endif		/* MD5_DIGEST_LENGTH */
#ifndef		MD5_DIGEST_STRING_LENGTH
# define	MD5_DIGEST_STRING_LENGTH	(2 * MD5_DIGEST_LENGTH + 1)
#endif		/* MD5_DIGEST_STRING_LENGTH */
#ifndef		MD5_DIGEST_B64_LENGTH
# define	MD5_DIGEST_B64_LENGTH		((4 * MD5_DIGEST_LENGTH + 2) / 3 + 1)
#endif		/* MD5_DIGEST_B64_LENGTH */

#endif		/* MD5_H */
