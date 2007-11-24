/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2007 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	<stdlib.h>
#include	<string.h>
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

#include	"xscrypt.h"

const	char	alnum[] = "./0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";

char *
mksalt()
{
	static	char	salt[3];

	srandom((unsigned long)time(NULL));
	salt[0] = alnum[random() % strlen(alnum)];
	salt[1] = alnum[random() % strlen(alnum)];
	salt[2] = '\0';
	return salt;
}
