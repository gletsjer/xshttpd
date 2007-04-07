/* Copyright (C) 2005, by Johan van Selst (johans@stack.nl) */

#include	<ldap.h>
#include	<stdio.h>

int	check_group (LDAP *, char *, const char *, const char *);
int	check_auth_ldap(const char *, const char *, const char *);
