/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		LDAP_H
#define		LDAP_H

#include	"config.h"

#ifdef		AUTH_LDAP
#include	<ldap.h>

bool	check_group (LDAP *, char *, const char *, const char *) WARNUNUSED;
bool	check_auth_ldap(const char *, const char *, const char *) WARNUNUSED;
bool	check_auth_ldap_full(const char *user, const char *pass, const struct ldap_auth *ldapinfo) WARNUNUSED;
#endif		/* AUTH_LDAP */

#endif		/* LDAP_H */
