/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<unistd.h>

int
seteuid(uid_t uid)
{
#ifdef		HAVE_SETRESUID
	return 	setresuid(-1, uid, -1);
#else		/* Not HAVE_SETRESUID */
	return	setreuid(-1, uid);
#endif		/* HAVE_SETRESUID */
}

int
setegid(gid_t gid)
{
#ifdef		HAVE_SETRESGID
	return	setresgid(-1, gid, -1);
#else		/* Not HAVE_SETRESGID */
	return	setregid(-1, gid);
#endif		/* HAVE_SETRESGID */
}

