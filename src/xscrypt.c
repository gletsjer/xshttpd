/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<unistd.h>
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

#include	"xscrypt.h"

extern	VOID
xs_encrypt DECL1(char *, buffer)
{
	strcpy(buffer, (char *)crypt(buffer, "xs"));
}
