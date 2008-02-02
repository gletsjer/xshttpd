/* Copyright (C) 2007-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	"decode.h"

#include	<sys/types.h>
#include	<openssl/md5.h>

char *
MD5Data(const unsigned char *data, size_t len, char *bufhex)
{
	char	buf[MD5_DIGEST_LENGTH];

	MD5((const unsigned char *)data, len, (unsigned char *)buf);
	hex_encode(buf, MD5_DIGEST_LENGTH, bufhex);
	return bufhex;
}

