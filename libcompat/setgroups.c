/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"
#include	<sys/types.h>

extern	int
setgroups(int ngroups, const gid_t *gidset)
{
	/* fake success */
	(void)ngroups;
	(void)gidset;
	return 0;
}
