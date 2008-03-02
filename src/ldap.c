/* Copyright (C) 2005 by Rink Springer (rink@stack.nl) */
/* Copyright (C) 2005-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#ifdef		AUTH_LDAP
#include	"htconfig.h"
#include	"ldap.h"
#include	"httpd.h"
#include	"malloc.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ldap.h>

bool
check_group (LDAP *ld, char *ldapdn, const char *user, const char *group)
{
	LDAPMessage	*res = NULL;
	LDAPMessage	*e;
	BerElement	*ber = NULL;
	char		filter[MYBUFSIZ];
	char		*a;
	char		*attrs[] = { NULL, NULL };
	bool		result = false;

	attrs[0] = strdup("memberUid");

	/*
	 * Search for the group first. Most directory have seperate branches
	 * for users/groups.
	 */
	snprintf (filter, MYBUFSIZ, "(cn=%s)", group);

	if (ldap_search_ext_s (ld, ldapdn, LDAP_SCOPE_SUBTREE, filter, attrs,
			0, NULL, NULL, NULL, 0, &res) != LDAP_SUCCESS)
		goto leave;
	e = ldap_first_entry (ld, res);
	if (e == NULL)
		goto leave;


	/*
	 * Look through all retrieved attributes (we only ask for member names,
	 * so we can just check any attribute for the username)
	 */
	for (a = ldap_first_attribute (ld, e, &ber); a != NULL;
	     a = ldap_next_attribute (ld, e, ber))
	{
		struct berval	**vals;

		vals = ldap_get_values_len (ld, e, a);
		if (vals != NULL)
		{
			int	i;

			for (i = 0; vals[i]->bv_val != NULL; i++)
			{
				if (!strcasecmp (vals[i]->bv_val, user))
					result = true;
			}

			ldap_value_free_len (vals);
		}

		ldap_memfree (a);
	}

leave:
	free(attrs[0]);

	if (res)
		ldap_msgfree (res);
	if (ber)
		ber_free (ber, 0);

	return result;
}

bool
check_auth_ldap(const char *authfile, const char *user, const char *pass)
{
	FILE	*af;
	char	line[LINEBUFSIZE];
	struct ldap_auth	ldap;

	memset(&ldap, 0, sizeof(ldap));

	/* LDAP may support empty passwords to do an anonymous bind. That's
	 * not what our idea of security is ... */
	if (!pass || !strlen(pass))
		return false;

	if (!(af = fopen(authfile, "r")))
	{
		server_error(403, "Authentication file is not available",
			"NOT_AVAILABLE");
		return false;
	}

	/*
 	 * Quick 'n dirty parser; usually the .xsauth file consists of
 	 * Uuser:hash entries. By accepting parameter=value entries, we
 	 * won't clash with that (since check_auth() will happily skip
 	 * over them)
 	 */
	while (fgets(line, LINEBUFSIZE, af))
	{
		char	*ptr;

		/* kill newlines and such, they confuse ldap */
		while ((ptr = strchr (line, '\r')) != NULL)
			*ptr = 0;
		if (!strncasecmp ("ldaphost=", line, 9))
                {
                        if (ldap.uri)
                                free(ldap.uri);
			MALLOC(ldap.uri, char, strlen(line));
			sprintf(ldap.uri, "ldap://%s", line + 9);
                }
		if (!strncasecmp ("ldapattr=", line, 9))
                {
                        if (ldap.attr)
                                free(ldap.attr);
			ldap.attr = strdup(line + 9);
                }
		if (!strncasecmp ("ldapuri=", line, 8))
                {
                        if (ldap.uri)
                                free(ldap.uri);
			ldap.uri = strdup(line + 8);
                }
		if (!strncasecmp ("ldapdn=", line, 7))
                {
                        if (ldap.dn)
                                free(ldap.dn);
			ldap.dn = strdup(line + 7);
                }
		if (!strncasecmp ("ldapversion=", line, 12))
			ldap.version = strtoul(line + 12, NULL, 10);
		if (!strncasecmp ("ldapgroups=", line, 11))
                {
                        if (ldap.groups)
                                free(ldap.groups);
			ldap.groups = strdup(line + 11);
                }
	}
	fclose(af);
	return check_auth_ldap_full(user, pass, &ldap);
}

bool
check_auth_ldap_full(const char *user, const char *pass, const struct ldap_auth *ldap)
{
	char	filter[MYBUFSIZ];
	char	*dn = NULL;
	LDAP	*ld;
	LDAPMessage	*res = NULL;
	LDAPMessage	*e;
	bool	allow = false;
	int	version = 3;
	struct	berval	cred;

	if (!ldap || !ldap->uri || !strlen(ldap->uri) ||
			!ldap->dn || !strlen(ldap->dn) ||
			!ldap->attr || !strlen(ldap->attr))
		/* LDAP config is incomplete */
		return false;

	if (ldap_initialize (&ld, ldap->uri) != LDAP_SUCCESS)
		return false;
	if (ldap->version)
		version = ldap->version;
	ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	/* copy password to rw variable */
	cred.bv_len = strlen(pass);
	cred.bv_val = cred.bv_len ? strdup(pass) : NULL;

	/*
	 * This search may look confusing. Basically, we do a search for the
	 * user in the tree given, _including all subtrees_.
	 */
	snprintf (filter, MYBUFSIZ - 1, "(%s=%s)", ldap->attr, user);

	if (ldap_search_ext_s (ld, ldap->dn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &res) != LDAP_SUCCESS)
		goto leave;
  
	/* simply grab the first item */
	e = ldap_first_entry (ld, res);
	if (e == NULL)
		goto leave;

	dn = ldap_get_dn (ld, e);
	if (dn == NULL)
		goto leave;

	/* the bind is the actual login, and verifies our password */ 
	if (ldap_sasl_bind_s (ld, dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL) != LDAP_SUCCESS)
		goto leave;

	if (!strcmp (ldap->groups, ""))
	{
		/* no groups specified, so it's a definite go */
		allow = true;
	}
	else
	{
		char	*curoffs;
		char	line[LINEBUFSIZE];

		curoffs = ldap->groups;
		for (;;)
		{
			/* isolate a group on a ',' boundery */
			char	*ptr = strchr (curoffs, ',');

			if (ptr == NULL)
				ptr = strchr (curoffs, 0);
			strlcpy (line, curoffs, (ptr - curoffs));

			if (check_group (ld, ldap->dn, user, line))
			{
				allow = true;
				break;
			}

			if (!*ptr)
				break;
			curoffs = ptr + 1;
		}
	}

leave:
	if (cred.bv_len)
		free(cred.bv_val);
	if (dn)
		ldap_memfree (dn);
	if (res)
		ldap_msgfree (res);
	ldap_unbind_ext_s (ld, NULL, NULL);
	return allow;
}

#endif		/* AUTH_LDAP */
