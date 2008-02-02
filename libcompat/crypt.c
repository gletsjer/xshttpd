/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#ifdef		HAVE_SSL
# include	<openssl/des.h>
#endif		/* HAVE_SSL */

char *
crypt(const char *buffer, const char *salt)
{
#ifdef		HAVE_SSL
	return DES_crypt(buffer, salt);
#else
	/* If you don't have a crypt() function, use plain-text pwd storage */
	return buffer;
#endif		/* HAVE_SSL */
}
