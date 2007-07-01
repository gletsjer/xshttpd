/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		XSCOUNTER_H
#define		XSCOUNTER_H

#include	"config.h"

#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */

#define	XSCOUNT_VERSION		((char)2)

typedef	struct	countstr
{
	char	filename[128];
	int	total, month, today;
	time_t	lastseen;
} countstr;

#endif		/* XSCOUNTER_H */
