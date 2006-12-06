/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: xscrypt.c,v 1.12 2006/12/06 20:56:56 johans Exp $ */

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
	return crypt(buffer, "xs");
#else		/* HAVE_CRYPT */
	/* If you don't have a crypt() function, use plain-text pwd storage */
	return buffer;
#endif		/* HAVE_CRYPT */
}
