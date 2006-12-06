/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: setgroups.c,v 1.5 2006/12/06 20:56:56 johans Exp $ */

#include	"config.h"
#include	<sys/types.h>

int
setgroups(int ngroups, const gid_t *gidset)
{
	/* fake success */
	(void)ngroups;
	(void)gidset;
	return 0;
}
