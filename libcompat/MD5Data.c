/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */
/* $Id: MD5Data.c,v 1.2 2007/03/16 21:53:49 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#include	<openssl/md5.h>

char *
MD5Data(const unsigned char *data, size_t len, char *bufhex)
{
	char	buf[MD5_DIGEST_LENGTH];

	MD5((const unsigned char *)data, len, buf);
	hex_encode(buf, MD5_DIGEST_LENGTH, bufhex);
	return bufhex;
}

