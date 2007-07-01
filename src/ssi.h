/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		SSI_H
#define		SSI_H

#include	<sys/types.h>

int	sendwithdirectives	(int, off_t *);
int	counter_versioncheck	(void);

#endif		/* SSI_H */
