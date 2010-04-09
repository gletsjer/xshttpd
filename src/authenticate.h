/* Copyright (C) 2007-2010 by Johan van Selst (johans@stack.nl) */

#ifndef		AUTHENTICATE_H
#define		AUTHENTICATE_H

#include	"config.h"
#include	<stdbool.h>

#define		REALM		"this page"
#define		MAX_NONCE_LENGTH	60

void	initnonce	(void);
bool	check_auth	(const char *, bool)	WARNUNUSED;
bool	check_auth_modules	(void)		WARNUNUSED;

#endif		/* AUTHENTICATE_H */
