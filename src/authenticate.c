/* Copyright (C) 2007-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<stdbool.h>
#ifdef		HAVE_LIBUTIL_H
#include	<libutil.h>
#else		/* HAVE_LIBUTIL_H */
# ifdef		HAVE_UTIL_H
# include	<util.h>
# endif		/* HAVE_UTIL_H */
#endif		/* HAVE_LIBUTIL_H */

#include	<openssl/des.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"decode.h"
#include	"ssl.h"
#include	"authenticate.h"
#include	"extra.h"
#include	"malloc.h"
#include	"modules.h"
#include	"hash.h"

static unsigned long	secret;
static const bool	rfc2617_digest = true;

static bool	get_crypted_password(const char *, const char *, char **, char **) WARNUNUSED;
static bool	check_basic_auth(const char *authfile) WARNUNUSED;
static bool	check_digest_auth(const char *authfile, bool *stale) WARNUNUSED;
static char 	*fresh_nonce(void) WARNUNUSED;
static bool	valid_nonce(const char *nonce) NONNULL WARNUNUSED;

static bool	denied_access(bool digest, bool stale);
static bool	denied_digest(bool stale);
static bool	denied_basic(void);

/* returns malloc()ed data! */
static bool
get_crypted_password(const char *authfile, const char *user, char **passwd, char **hash)
{
	char	*line;
	FILE	*af;
	size_t	sz;

	if (!(af = fopen(authfile, "r")))
		return false;

	if (passwd)
		*passwd = NULL;
	if (hash)
		*hash = NULL;

	while ((line = fparseln(af, &sz, NULL, NULL, 0)))
	{
		char	*lpass, *lhash;

		if (sz < strlen(user) + 2)
		{
			free(line);
			continue;
		}

		if (strncmp(line + 1, user, strlen(user)) ||
				line[strlen(user)+1] != ':')
		{
			free(line);
			continue;
		}

		if ((lpass = strchr(line, ':')))
			lpass++;
		else
		{
			free(line);
			fclose(af);
			return false;
		}
		if ((lhash = strchr(lpass, ':')))
			*lhash++ = '\0';

		if (passwd)
			STRDUP(*passwd, lpass);
		if (hash)
			STRDUP(*hash, lhash);
		free(line);
		fclose(af);
		return true; /* found! */
	}
	fclose(af);
	return false;
}

static bool
check_basic_auth(const char *authfile)
{
	char		*line, *search, *passwd, *find;
	bool		allow;

	/* basic auth */
	STRDUP(line, env.authorization);
	find = strchr(line, '\0');
	while ((find > line) && (*(find - 1) < ' '))
		*(--find) = 0;
	for (search = line + 5; *search && isspace(*search); search++)
		/* DO NOTHING */ ;
	uudecode(search);
	if ((find = strchr(search, ':')))
	{
		*find++ = 0;
		setenv("AUTH_TYPE", "Basic", 1);
		setenv("REMOTE_USER", search, 1);
		setenv("REMOTE_PASSWORD", find, 1);
	}
	passwd = NULL;
	if (!get_crypted_password(authfile, search, &passwd, NULL) || !passwd)
	{
		free(line);
		return false;
	}

	allow = !strcmp(passwd, DES_crypt(find, passwd));
	free(passwd);
	free(line);
	return allow;
}

static bool
check_digest_auth(const char *authfile, bool *stale)
{
	char		ha2[MD5_DIGEST_STRING_LENGTH],
			digest[MD5_DIGEST_STRING_LENGTH],
			*line;
	struct		mapping		*authreq;
	char		*user, *realm, *nonce, *cnonce, *uri,
			*response, *qop, *nc;
	char		*passwd, *a2, *digplain, *ha1;
	char		*idx, *val;
	size_t		sz, fields, len;

	*stale = false;

	/* digest auth, rfc 2069 */
	if (strncmp(env.authorization, "Digest ", 7))
		return false; /* fail */
	STRDUP(line, env.authorization + 7);

	/* grab element from line */
	fields = eqstring_to_array(line, NULL);
	if (!fields)
	{
		free(line);
		return false;
	}
	MALLOC(authreq, struct mapping, fields);
	fields = eqstring_to_array(line, authreq);
	user = realm = nonce = cnonce = uri = response = qop = nc = NULL;
	for (sz = 0; sz < fields; sz++)
	{
		idx = authreq[sz].index;
		val = authreq[sz].value;
		if (!strcmp(idx, "username"))
			user = val;
		else if (!strcmp(idx, "realm"))
			realm = val;
		else if (!strcmp(idx, "nonce"))
			nonce = val;
		else if (!strcmp(idx, "cnonce"))
			cnonce = val;
		else if (!strcmp(idx, "uri"))
			uri = val;
		else if (!strcmp(idx, "response"))
			response = val;
		else if (!strcmp(idx, "qop"))
			qop = val;
		else if (!strcmp(idx, "nc"))
			nc = val;
		/* not interested in other keywords */
	}

	if (!user || !realm || !nonce || !uri || !response)
	{
		free(authreq);
		free(line);
		return false; /* fail */
	}
	passwd = ha1 = NULL;
	if (!get_crypted_password(authfile, user, &passwd, &ha1) || !passwd)
	{
		free(authreq);
		free(line);
		return false; /* not found */
	}

	free(passwd);
	if (!ha1)
	{
		free(authreq);
		free(line);
		return false;
	}

	/* obtain h(a1) from file */
	if (strlen(ha1) > MD5_DIGEST_STRING_LENGTH)
	{
		free(ha1);
		free(authreq);
		free(line);
		return false; /* no valid hash */
	}

	/* calculate h(a2) */
	len = asprintf(&a2, "%s:%s", env.request_method, uri);
	md5data(a2, len, ha2);
	free(a2);

	/* calculate digest from h(a1) and h(a2) */
	if (!qop)
		len = asprintf(&digplain, "%s:%s:%s", ha1, nonce, ha2);
	else
		len = asprintf(&digplain, "%s:%s:%s:%s:%s:%s",
			ha1, nonce, nc, cnonce, qop, ha2);
	md5data(digplain, len, digest);
	free(digplain);
	free(ha1);

	if (strcmp(response, digest))
	{
		free(authreq);
		free(line);
		return false; /* no match */
	}

	if (!valid_nonce(nonce))
	{
		*stale = true;
		free(authreq);
		free(line);
		return false; /* invalid nonce */
	}

	setenv("AUTH_TYPE", "Digest", 1);
	setenv("REMOTE_USER", user, 1);
	free(authreq);
	free(line);
	return true;
}

bool
denied_access(bool digest, bool stale)
{
	char		*errmsg;

	asprintf(&errmsg,
		"\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
		"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
		"<head><title>Wrong password</title></head>\n"
		"<body><h1>Wrong user/password combination</h1>\n"
		"You don't have permission to view this page.\n"
		"</body></html>\n");
	if (session.headers)
	{
		secprintf("%s 401 Wrong user/password combination\r\n",
			env.server_protocol);
		if (digest)
		{
			secprintf("WWW-Authenticate: digest realm=\""
				REALM "\", nonce=\"%s\"%s%s\r\n",
				fresh_nonce(),
				rfc2617_digest
				 ? ", qop=\"auth\", algorithm=md5"
				 : "",
				stale ? ", stale=true" : "");
		}
		else
			secputs("WWW-Authenticate: basic realm=\""
				REALM "\"\r\n");
		secprintf("Content-length: %zu\r\n", strlen(errmsg));
		stdheaders(1, 1, 1);
	}
	secputs(errmsg);
	free(errmsg);
	(void)stale;
	return false;
}

bool
denied_basic(void)
{
	return denied_access(false, false);
}

bool
denied_digest(bool stale)
{
	return denied_access(true, stale);
}

bool
check_auth_modules(void)
{
	bool	allowed = true;
	bool	digest = false;

	if (!env.authorization)
	{
		for (struct module *mod, **mods = modules; (mod = *mods); mods++)
			if (mod->auth_basic)
			{
				if (!mod->auth_basic("", ""))
					return denied_basic();
			}
			else if (mod->auth_digest)
			{
				if (!mod->auth_digest("", ""))
					return denied_digest(false);
			}

		/* Every module needs to grant access */
		if (allowed)
			return true;
	}

	/* Parse authentication line */
	if (!strncasecmp(env.authorization, "Basic", 5))
		digest = false;
	else if (!strncasecmp(env.authorization, "Digest", 6))
		digest = true;
	else
		return denied_basic();

	/* Basic authentication */
	if (!digest)
	{
		char	*line, *user, *pass;

		STRDUP(line, env.authorization);
		pass = strchr(line, '\0');
		while ((pass > line) && (*(pass - 1) < ' '))
			*(--pass) = 0;
		for (user = line + 5; *user && isspace(*user); user++)
			/* DO NOTHING */ ;
		uudecode(user);
		if (!(pass = strchr(user, ':')))
			return denied_basic();

		*pass++ = 0;
		for (struct module *mod, **mods = modules;
				(mod = *mods); mods++)
			if (mod->auth_basic)
				/* Every module needs to grant access */
				allowed &= mod->auth_basic(user, pass);
		/* At least one module needs to deny access */
		return allowed ? true : denied_basic();
	}

	/* TODO: implement digest modules */

	return true;
}

bool
check_auth(const char *authfile, bool quiet)
{
	bool		digest, stale;
	FILE		*af;

	if (!authfile)
	{
		if (!quiet)
			server_error(403,
				"Authentication information is not available",
				"NOT_AVAILABLE");
		return false;
	}

	if (authfile && !(af = fopen(authfile, "r")))
	{
		if (!quiet)
			server_error(403,
				"Authentication file is not available",
				"NOT_AVAILABLE");
		return false;
	}

	/* Determine authentication type from file: basic / digest */
	if (authfile)
	{
		char		*p, *line;
		size_t		sz;
		int		i = 1;

		if ((line = fgetln(af, &sz)))
			for (i = 0, p = line; p < line + sz; p++)
				if (':' == *p)
					i++;
		digest = i > 1;
		fclose(af);
	}
	else
		digest = false;

	if (!env.authorization ||
		(strncasecmp(env.authorization, "Basic", 5) &&
		 strncasecmp(env.authorization, "Digest", 6)))
	{
		if (quiet)
			return false;

		return denied_access(digest, false);
	}
	stale = false;
	if ('d' == env.authorization[0] || 'D' == env.authorization[0])
	{
		if (check_digest_auth(authfile, &stale))
			return true;
	}
	else
	{
		if (check_basic_auth(authfile))
			return true;
	}

	if (quiet)
		return false;

	return denied_access(digest, stale);
}

void
initnonce()
{
	srandomdev();
	secret = random();
}

static char *
fresh_nonce(void)
{
	static char	nonce[MAX_NONCE_LENGTH];
	char		bufhex[MD5_DIGEST_STRING_LENGTH];
	const time_t	ts = time(NULL);
	char	*buf;
	size_t	len;

	len = asprintf(&buf, "%" PRItimex ":%lu:%s",
		ts, secret, env.remote_addr);
	md5data(buf, len, bufhex);
	free(buf);

	snprintf(nonce, MAX_NONCE_LENGTH, "%" PRItimex ":%s", ts, bufhex);
	return nonce;
}

static bool
valid_nonce(const char *nonce)
{
	char	bufhex[MD5_DIGEST_STRING_LENGTH];
	const char	*ptr;
	char	*buf;
	time_t	ts;
	size_t	len;

	if (!nonce)
		return false;		/* invalid */
	if (!(ptr = strchr(nonce, ':')))
		return false;
	ptr++;
	ts = strtol(nonce, NULL, 16);

	len = asprintf(&buf, "%" PRItimex ":%lu:%s",
		ts, secret, env.remote_addr);
	md5data(buf, len, bufhex);
	free(buf);

	if (strcmp(ptr, bufhex))
		return false;

	/* fresh for 1 hour */
	return ts + 3600 > time(NULL);
}
