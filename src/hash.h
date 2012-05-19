#ifndef		MD5_H
#define		MD5_H

#include	"config.h"
#include	<stdbool.h>
#include	<openssl/md5.h>

#ifndef		MD5_DIGEST_LENGTH
# define	MD5_DIGEST_LENGTH		16
#endif		/* MD5_DIGEST_LENGTH */
#ifndef		MD5_DIGEST_STRING_LENGTH
# define	MD5_DIGEST_STRING_LENGTH	(2 * MD5_DIGEST_LENGTH + 1)
#endif		/* MD5_DIGEST_STRING_LENGTH */
#ifndef		MD5_DIGEST_B64_LENGTH
# define	MD5_DIGEST_B64_LENGTH		((4 * MD5_DIGEST_LENGTH + 2) / 3 + 1)
#endif		/* MD5_DIGEST_B64_LENGTH */

char	*generate_ha1	(const char * const, const char * const) NONNULL;
bool	md5data		(const char * const, size_t, char *) NONNULL;
bool	md5file		(const char * const, char *) NONNULL;
void	checksum_init	(void);
void	checksum_update	(const char * const, size_t);
char	*checksum_final	(void);
char	*checksum_file	(const char * const);

#endif		/* MD5_H */
