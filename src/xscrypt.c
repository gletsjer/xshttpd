/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<unistd.h>
#include	<string.h>
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

#include	"xscrypt.h"

extern	VOID
xs_encrypt DECL1(char *, buffer)
{
#ifdef		HAVE_CRYPT
	/* If you don't have a crypt() function, use plain-text pwd storage */
	strcpy(buffer, (char *)crypt(buffer, "xs"));
#endif		/* HAVE_CRYPT */
}
