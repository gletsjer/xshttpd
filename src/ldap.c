/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */
/* $Id: ldap.c,v 1.4 2005/07/06 11:27:30 johans Exp $ */

#include	"config.h"
#include	"ldap.h"
#include	"httpd.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ldap.h>

int
check_group (LDAP *ld, char *ldapdn, const char *user, const char *group)
{
	LDAPMessage	*res = NULL;
	LDAPMessage	*e;
	BerElement	*ber = NULL;
	char		filter[MYBUFSIZ];
	char		*a;
	char		**vals;
	char		*attrs[] = { NULL, NULL };
	int		result = 0, i;

	attrs[0] = strdup("memberUid");

	/*
	 * Search for the group first. Most directory have seperate branches
	 * for users/groups.
	 */
	snprintf (filter, MYBUFSIZ, "(cn=%s)", group);

	if (ldap_search_s (ld, ldapdn, LDAP_SCOPE_SUBTREE, filter, attrs,
			0, &res) != LDAP_SUCCESS)
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
		vals = ldap_get_values (ld, e, a);
		if (vals != NULL)
		{
			for (i = 0; vals[i] != NULL; i++)
			{
				if (!strcasecmp (vals[i], user))
					result++;
			}

			ldap_value_free (vals);
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

int
check_auth_ldap(FILE *authfile, const char *user, const char *pass)
{
	char	ldapuri[MYBUFSIZ];
	char	ldapdn[MYBUFSIZ];
	char	ldapattr[MYBUFSIZ];
	char	ldapgroups[MYBUFSIZ];
	char	line[MYBUFSIZ];
	int	ldapversion;
	char	filter[MYBUFSIZ];
	char	*dn = NULL;
	char	*ptr;
	char	*curoffs;
	LDAP	*ld;
	LDAPMessage	*res = NULL;
	LDAPMessage	*e;
	int	ok = 1;

	strcpy (ldapuri, ""); strcpy (ldapdn, ""); strcpy (ldapattr, "uid");
	strcpy (ldapgroups, ""); ldapversion = 3;

	/* LDAP may support empty passwords to do an anonymous bind. That's
	 * not what our idea of security is ... */
	if (!strlen (pass))
		return(1);

	/*
 	 * Quick 'n dirty parser; usually the .xsauth file consists of
 	 * Uuser:hash entries. By accepting parameter=value entries, we
 	 * won't clash with that (since check_auth() will happily skip
 	 * over them)
 	 */
	rewind(authfile);
	while (fgets(line, MYBUFSIZ, authfile))
	{
		/* kill newlines and such, they confuse ldap */
		while ((ptr = strchr (line, '\n')) != NULL)
			*ptr = 0;
		while ((ptr = strchr (line, '\r')) != NULL)
			*ptr = 0;
		if (!strncasecmp ("ldaphost=", line, 9))
			sprintf (ldapuri, "ldap://%s", (line + 9));
		if (!strncasecmp ("ldapattr=", line, 9))
			strcpy (ldapattr, (line + 9));
		if (!strncasecmp ("ldapuri=", line, 8))
			strcpy (ldapuri, (line + 8));
		if (!strncasecmp ("ldapdn=", line, 7))
			strcpy (ldapdn, (line + 7));
		if (!strncasecmp ("ldapversion=", line, 12))
			ldapversion = atoi (line + 12);
		if (!strncasecmp ("ldapgroups=", line, 11))
			strcpy (ldapgroups, (line + 11));
	}

	if ((!strlen (ldapuri)) || (!strlen(ldapdn)) || (!strlen (ldapattr)))
	{
		/* LDAP config is incomplete */
		return(1);
	}

	if (ldap_initialize (&ld, ldapuri) != LDAP_SUCCESS)
		return(1);
	ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &ldapversion);

	/*
	 * This search may look confusing. Basically, we do a search for the
	 * user in the tree given, _including all subtrees_.
	 */
	snprintf (filter, MYBUFSIZ - 1, "(%s=%s)", ldapattr, user);

	if (ldap_search_s (ld, ldapdn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, &res) != LDAP_SUCCESS)
		goto leave;
  
	/* simply grab the first item */
	e = ldap_first_entry (ld, res);
	if (e == NULL)
		goto leave;

	dn = ldap_get_dn (ld, e);
	if (dn == NULL)
		goto leave;

	/* the bind is the actual login, and verifies our password */ 
	if (ldap_bind_s (ld, dn, pass, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS)
		goto leave;

	if (!strcmp (ldapgroups, ""))
	{
		/* no groups specified, so it's a definite go */
		ok = 0;
	}
	else
	{
		curoffs = ldapgroups;
		while (1)
		{
			/* isolate a group on a ',' boundery */
			ptr = strchr (curoffs, ',');
			if (ptr == NULL)
				ptr = strchr (curoffs, 0);
			strlcpy (line, curoffs, (ptr - curoffs));

			if (check_group (ld, ldapdn, user, line))
			{
				ok = 0;
				break;
			}

			if (!*ptr)
				break;
			curoffs = ptr + 1;
		}
	}

	/* only close file if ldap is successful */
	if (!ok)
		fclose (authfile);

leave:
	if (dn)
		ldap_memfree (dn);
	if (res)
		ldap_msgfree (res);
	ldap_unbind (ld);

	return ok;
}
