/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		LDAP_H
#define		LDAP_H

#include	"config.h"

#ifdef		AUTH_LDAP
#include	<ldap.h>

int	check_group (LDAP *, char *, const char *, const char *);
int	check_auth_ldap(const char *, const char *, const char *);
int	check_auth_ldap_full(const char *user, const char *pass, const struct ldap_auth *ldapinfo);
#endif		/* AUTH_LDAP */

#endif		/* LDAP_H */
