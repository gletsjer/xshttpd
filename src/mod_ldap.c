/* Copyright (C) 2005 by Rink Springer (rink@stack.nl) */
/* Copyright (C) 2005-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	<ldap.h>

#include	"ldap.h"
#include	"malloc.h"
#include	"pcre.h"
#include	"modules.h"
#include	"constants.h"

struct ldap_auth
{
	char	*uri, *attr, *dn, *groups, *filter;
	int	version;
} ldap = { NULL, NULL, NULL, NULL, NULL, 3 };

static bool	check_group (LDAP *, char *, const char *, const char *) WARNUNUSED;
static bool	check_auth_ldap(const char *, const char *, const char *) WARNUNUSED;
static bool	check_auth_ldap_full(const char *user, const char *pass) WARNUNUSED;

bool		ldap_config_local(const char *, const char *);

static bool
check_group (LDAP *ld, char *ldapdn, const char *user, const char *group)
{
	LDAPMessage	*res = NULL;
	LDAPMessage	*e;
	BerElement	*ber = NULL;
	char		*filter;
	char		*a;
	char		*attrs[] = { NULL, NULL };
	bool		result = false;

	STRDUP(attrs[0], "memberUid");

	/*
	 * Search for the group first. Most directory have separate branches
	 * for users/groups.
	 */
	ASPRINTF(&filter, "(cn=%s)", group);

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
	FREE(filter);
	FREE(attrs[0]);

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
	char	*line;
	size_t	sz;

	memset(&ldap, 0, sizeof(ldap));

	/* LDAP may support empty passwords to do an anonymous bind. That's
	 * not what our idea of security is ... */
	if (!pass || !strlen(pass))
		return false;

	if (!(af = fopen(authfile, "r")))
		return false;

	/*
 	 * Quick 'n dirty parser; usually the .xsauth file consists of
 	 * Uuser:hash entries. By accepting parameter=value entries, we
 	 * won't clash with that (since check_auth() will happily skip
 	 * over them)
 	 */
	while ((line = fgetln(af, &sz)))
	{
		char	*ptr;

		/* kill newlines and such, they confuse ldap */
		if (!(ptr = memchr(line, '\n', sz)))
			continue;
		*ptr = '\0';
		if ((ptr = strchr(line, '\r')))
			*ptr = '\0';
		if (!strncasecmp ("ldaphost=", line, 9))
                {
                        if (ldap.uri)
                                FREE(ldap.uri);
			MALLOC(ldap.uri, char, strlen(line));
			sprintf(ldap.uri, "ldap://%s", line + 9);
                }
		if (!strncasecmp ("ldapattr=", line, 9))
                {
                        if (ldap.attr)
                                FREE(ldap.attr);
			STRDUP(ldap.attr, line + 9);
                }
		if (!strncasecmp ("ldapuri=", line, 8))
                {
                        if (ldap.uri)
                                FREE(ldap.uri);
			STRDUP(ldap.uri, line + 8);
                }
		if (!strncasecmp ("ldapdn=", line, 7))
                {
                        if (ldap.dn)
                                FREE(ldap.dn);
			STRDUP(ldap.dn, line + 7);
                }
		if (!strncasecmp ("ldapversion=", line, 12))
			ldap.version = strtoul(line + 12, NULL, 10);
		if (!strncasecmp ("ldapgroups=", line, 11))
                {
                        if (ldap.groups)
                                FREE(ldap.groups);
			STRDUP(ldap.groups, line + 11);
                }
		if (!strncasecmp ("ldapfilter=", line, 11))
                {
                        if (ldap.filter)
                                FREE(ldap.filter);
			STRDUP(ldap.filter, line + 11);
                }
	}
	fclose(af);
	return check_auth_ldap_full(user, pass);
}

bool
check_auth_ldap_full(const char *user, const char *pass)
{
	char	*filter;
	char	*dn = NULL;
	LDAP	*ld;
	LDAPMessage	*res = NULL;
	LDAPMessage	*e;
	bool	allow = false;
	int	version = 3;
	struct	berval	cred;

	/* No directory name - then no checking */
	if (!ldap.dn)
		return true;

	if (!ldap.uri || !strlen(ldap.uri) ||
			!ldap.dn || !strlen(ldap.dn) ||
			!(ldap.attr || ldap.filter) ||
			!strlen(ldap.attr ? ldap.attr : ldap.filter))
		/* LDAP config is incomplete */
		return false;

	if (ldap_initialize (&ld, ldap.uri) != LDAP_SUCCESS)
		return false;
	if (ldap.version)
		version = ldap.version;
	ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	/* copy password to rw variable */
	cred.bv_len = strlen(pass);
	STRDUP(cred.bv_val, cred.bv_len ? pass : NULL);

	/* copy filter, filling in $user */
	if (ldap.filter)
	{
		/* This code is seriously broken. Compare with man page. */
		STRDUP(filter, ldap.filter);
		if (!filter && !ldap.attr)
		{
			FREE(cred.bv_val);
			FREE(filter);
			return false;
		}
		if (ldap.attr)
		{
			char *newfilter = NULL;
			/* combine ldap.filter and $attr query */
			ASPRINTF (&newfilter, "(&(%s=%s)(%s))",
				ldap.attr, user,
				filter ? filter : ldap.filter);
			FREE(filter);
			filter = newfilter;
		}
	}
	else if (ldap.attr)
		ASPRINTF (&filter, "(%s=%s)", ldap.attr, user);
	else
		ASPRINTF (&filter, "(uid=%s)", user);

	/*
	 * This search may look confusing. Basically, we do a search for the
	 * user in the tree given, _including all subtrees_.
	 */

	if (ldap_search_ext_s (ld, ldap.dn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &res) != LDAP_SUCCESS)
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

	if (!ldap.groups || !strcmp (ldap.groups, ""))
	{
		/* no groups specified, so it's a definite go */
		allow = true;
	}
	else
	{
		char	*curoffs;
		char	line[LINEBUFSIZE];

		curoffs = ldap.groups;
		for (;;)
		{
			/* isolate a group on a ',' boundery */
			char	*ptr = strchr (curoffs, ',');

			if (ptr == NULL)
				ptr = strchr (curoffs, 0);
			strlcpy (line, curoffs, (ptr - curoffs));

			if (check_group (ld, ldap.dn, user, line))
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
	FREE(filter);
	if (cred.bv_len)
		FREE(cred.bv_val);
	if (dn)
		ldap_memfree (dn);
	if (res)
		ldap_msgfree (res);
	ldap_unbind_ext_s (ld, NULL, NULL);
	return allow;
}

bool
ldap_config_local(const char *name, const char *value)
{
	/* Erase local configuration. */
	if (!name && !value) {
		FREE(ldap.uri);
		FREE(ldap.attr);
		FREE(ldap.dn);
		FREE(ldap.groups);
		FREE(ldap.filter);
		ldap.version = 0;
	}
	/* Parse local configuration. */
	else if (!strcasecmp(name, "LdapHost"))
	{
		FREE(ldap.uri);
		ASPRINTF(&ldap.uri, "ldap://%s", value);
	}
	else if (!strcasecmp(name, "LdapURI"))
	{
		FREE(ldap.uri);
		STRDUP(ldap.uri, value);
	}
	else if (!strcasecmp(name, "LdapAttr"))
	{
		FREE(ldap.attr);
		STRDUP(ldap.attr, value);
	}
	else if (!strcasecmp(name, "LdapDN"))
	{
		FREE(ldap.dn);
		STRDUP(ldap.dn, value);
	}
	else if (!strcasecmp(name, "LdapVersion"))
	{
		ldap.version = strtoul(value, NULL, 10);
	}
	else if (!strcasecmp(name, "LdapGroups"))
	{
		FREE(ldap.groups);
		STRDUP(ldap.groups, value);
	}
	else if (!strcasecmp(name, "LdapFilter"))
	{
		FREE(ldap.filter);
		STRDUP(ldap.filter, value);
	}
	else
		return false;

	return true;
}

struct module ldap_module =
{
	.name = "ldap authentication",
	.init = NULL,
	.auth_basic = check_auth_ldap_full,
	.config_local = ldap_config_local,
};

