/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<unistd.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"decode.h"
#include	"authenticate.h"
#include	"malloc.h"
#include	"hash.h"

/* sizeof(hash) >= MD5_DIGEST_STRING_LENGTH */
char *
generate_ha1(const char * const user, const char * const passwd)
{
	static	char	ha1[MD5_DIGEST_STRING_LENGTH];
	char		*a1;
	size_t		len;

	/* calculate h(a1) */
	ASPRINTFVAL(len, &a1, "%s:%s:%s", user, REALM, passwd);
	md5data(a1, len, ha1);
	FREE(a1);

	return ha1;
}

bool
md5data(const char * const data, size_t len, char *bufhex)
{
	char    buf[MD5_DIGEST_LENGTH];

	MD5((const unsigned char *)data, len, (unsigned char *)buf);
	hex_encode(buf, MD5_DIGEST_LENGTH, bufhex);
	return true;
}

bool
md5file(const char * const filename, char *hash)
{
	int		fd, len;
	MD5_CTX		md5_ctx;
	unsigned char	buf[BUFSIZ];

	if ((fd = open(filename, O_RDONLY)) < 0)
		return false;

	MD5_Init(&md5_ctx);
	while ((len = read(fd, buf, sizeof(buf))) > 0)
		MD5_Update(&md5_ctx, buf, len);

	close(fd);
	return MD5_Final((unsigned char *)hash, &md5_ctx);
}

bool		use_checksum;
MD5_CTX		md5context;

void
checksum_init(void)
{
	use_checksum = true;
	MD5_Init(&md5context);
}

void
checksum_update(const char * const buffer, size_t count)
{
	if (use_checksum)
		MD5_Update(&md5context, buffer, count);
}

char *
checksum_final(void)
{
	static char	base64_data[MD5_DIGEST_B64_LENGTH];
	char		digest[MD5_DIGEST_LENGTH];

	if (!use_checksum)
		return NULL;
	/* turn off after use */
	use_checksum = false;

	MD5_Final((unsigned char *)digest, &md5context);
	base64_encode(digest, MD5_DIGEST_LENGTH, base64_data);
	return base64_data;
}

char *
checksum_file(const char * const filename)
{
	static char	base64_data[MD5_DIGEST_B64_LENGTH];
	char		digest    [MD5_DIGEST_LENGTH];
	char		hex_digest[MD5_DIGEST_STRING_LENGTH];

	if (!(md5file(filename, hex_digest)))
		return NULL;

	hex_decode(hex_digest, MD5_DIGEST_STRING_LENGTH - 1, digest);
	base64_encode(digest, MD5_DIGEST_LENGTH, base64_data);
	return base64_data;
}

