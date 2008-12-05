/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	<openssl/des.h>

inline char *
crypt(const char *buffer, const char *salt)
{
	return DES_crypt(buffer, salt);
}
