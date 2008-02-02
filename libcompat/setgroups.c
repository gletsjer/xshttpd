/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

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
