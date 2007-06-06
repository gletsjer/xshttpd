/* Copyright (C) 2005, by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	<stdio.h>
#ifdef		AUTH_LDAP
#include	<ldap.h>
#endif		/* AUTH_LDAP */

#ifdef		AUTH_LDAP
int	check_group (LDAP *, char *, const char *, const char *);
int	check_auth_ldap(const char *, const char *, const char *);
int	check_auth_ldap_full(const char *user, const char *pass, const struct ldap_auth *ldapinfo);
#endif		/* AUTH_LDAP */

