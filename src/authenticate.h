/* Copyright (C) 2007-2008 by Johan van Selst (johans@stack.nl) */

#ifndef		AUTHENTICATE_H
#define		AUTHENTICATE_H

#include	"config.h"
#include	<stdbool.h>

#include	"ldap.h"

#define		REALM		"this page"
#define		MAX_NONCE_LENGTH	60

void	initnonce	(void);
bool	check_auth	(const char *, const struct ldap_auth *, bool)	WARNUNUSED;

#endif		/* AUTHENTICATE_H */
