/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */
/* $Id: MD5Data.c,v 1.1 2007/03/13 13:33:18 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#include	"md5.h"

char *
MD5Data(const unsigned char *data, size_t len, char *bufhex)
{
	char	buf[MD5_DIGEST_LENGTH];

	MD5((const unsigned char *)data, len, buf);
	hex_encode(buf, MD5_DIGEST_LENGTH, bufhex);
	return bufhex;
}
