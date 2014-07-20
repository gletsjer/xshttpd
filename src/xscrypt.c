/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2013 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<string.h>

#include	"xscrypt.h"

const	char	alnum[] = "./0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";

char *
mksalt(void)
{
	static	char	salt[CRYPT_SALT_LEN + 1];

	srandomdev();
	for (int i = 0; i < CRYPT_SALT_LEN; i++)
		salt[i] = alnum[random() % strlen(alnum)];
	salt[CRYPT_SALT_LEN] = '\0';
	return salt;
}
