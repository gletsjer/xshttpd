/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<unistd.h>
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

#include	"xscrypt.h"

char *
xs_encrypt(const char *buffer)
{
#ifdef		HAVE_CRYPT
	/* If you don't have a crypt() function, use plain-text pwd storage */
	return crypt(buffer, "xs");
#else		/* HAVE_CRYPT */
	return buffer;
#endif		/* HAVE_CRYPT */
}
