/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<unistd.h>
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

#include	"htconfig.h"
#include	"httpd.h"
#include	"decode.h"
#include	"ssl.h"
#include	"authenticate.h"
#include	"ldap.h"
#include	"extra.h"

char		authentication[MYBUFSIZ];
static unsigned long int	secret;
static const int	rfc2617_digest = 1;

static int	get_crypted_password(const char *, const char *, char **, char **) WARNUNUSED;
static int	check_basic_auth(const char *authfile, const struct ldap_auth *) WARNUNUSED;
#ifdef		HAVE_MD5
static int	check_digest_auth(const char *authfile) WARNUNUSED;
static char 	*fresh_nonce(void) WARNUNUSED;
static int	valid_nonce(const char *nonce)NONNULL WARNUNUSED;
#endif		/* HAVE_MD5 */

/* returns malloc()ed data! */
static int
get_crypted_password(const char *authfile, const char *user, char **passwd, char **hash)
{
	char	line[LINEBUFSIZE];
	FILE	*af;

	if (!(af = fopen(authfile, "r")))
		return 0;

	if (passwd)
		*passwd = NULL;
	if (hash)
		*hash = NULL;

	while (fgets(line, LINEBUFSIZE, af))
	{
		char	*lpass, *lhash, *eol;

		if (strncmp(line + 1, user, strlen(user)) ||
				line[strlen(user)+1] != ':')
			continue;

		if ((lpass = strchr(line, ':')))
			lpass++;
		else
		{
			fclose(af);
			return 0;
		}
		if ((lhash = strchr(lpass, ':')))
			*lhash++ = '\0';
		if ((eol = strchr(lhash ? lhash : lpass, '\r')) ||
				(eol = strchr(lhash ? lhash : lpass, '\n')))
			*eol = '\0';

		if (passwd)
			*passwd = strdup(lpass);
		if (hash)
			*hash = lhash ? strdup(lhash) : NULL;
		fclose(af);
		return 1; /* found! */
	}
	fclose(af);
	return 0;
}

static int
check_basic_auth(const char *authfile, const struct ldap_auth *ldap)
{
	char		*search, *line, *passwd, *find;
	int		reject;

	/* basic auth */
	line = strdup(authentication);
	find = line + strlen(line);
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

#ifdef AUTH_LDAP
		/*
		 * Try to do an LDAP auth first. This is because xs_encrypt()
		 * may alter the buffer, in which case we compare garbage.
		 */
		if (authfile && !check_auth_ldap(authfile, search, find))
		{
			free(line);
			return(0);
		}
		else if (ldap && !check_auth_ldap_full(search, find, ldap))
		{
			free(line);
			return(0);
		}
#endif /* AUTH_LDAP */
	}
	passwd = NULL;
	if (!get_crypted_password(authfile, search, &passwd, NULL) || !passwd)
	{
		free(line);
		return 1;
	}

	reject = !strcmp(passwd, crypt(find, passwd));
	free(line);
	free(passwd);
	(void)ldap;
	return reject;
}

#ifdef		HAVE_MD5
static int
check_digest_auth(const char *authfile)
{
	char		ha2[MD5_DIGEST_STRING_LENGTH],
			digest[MD5_DIGEST_STRING_LENGTH],
			line[MYBUFSIZ];
	struct		mapping		*authreq;
	const char	*user, *realm, *nonce, *cnonce, *uri,
			*response, *qop, *nc;
	char		*passwd, *a2, *digplain, *ha1;
	char		*idx, *val;
	size_t		sz, fields, len;

	/* digest auth, rfc 2069 */
	if (strncmp(authentication, "Digest ", 7))
		return 1; /* fail */
	strlcpy(line, authentication + 7, MYBUFSIZ);
	if (!*line)
		return 1;

	/* grab element from line */
	fields = eqstring_to_array(line, NULL);
	if (!fields)
		return 1;
	authreq = (struct mapping *)malloc(fields * sizeof (struct mapping));
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
	free(authreq);

	if (!user || !realm || !nonce || !uri || !response)
		return 1; /* fail */
	passwd = ha1 = NULL;
	if (!get_crypted_password(authfile, user, &passwd, &ha1) || !passwd)
		return 1; /* not found */

	free(passwd);
	if (!ha1)
		return 1;

	/* obtain h(a1) from file */
	if (strlen(ha1) > MD5_DIGEST_STRING_LENGTH)
	{
		free(ha1);
		return 1; /* no valid hash */
	}

	/* calculate h(a2) */
	len = asprintf(&a2, "%s:%s", getenv("REQUEST_METHOD"), uri);
	MD5Data((unsigned char *)a2, len, ha2);
	free(a2);

	/* calculate digest from h(a1) and h(a2) */
	if (!qop)
		len = asprintf(&digplain, "%s:%s:%s", ha1, nonce, ha2);
	else
		len = asprintf(&digplain, "%s:%s:%s:%s:%s:%s",
			ha1, nonce, nc, cnonce, qop, ha2);
	MD5Data((unsigned char *)digplain, len, digest);
	free(digplain);
	free(ha1);

	if (strcmp(response, digest))
		return 1; /* no match */

	if (!valid_nonce(nonce))
		return 2; /* invalid nonce */

	setenv("AUTH_TYPE", "Digest", 1);
	setenv("REMOTE_USER", user, 1);
	return 0;
}
#endif		/* HAVE_MD5 */

int
check_auth(const char *authfile, const struct ldap_auth *ldap)
{
	char		*errmsg;
	int		digest, rv = 0;
	FILE		*af;

	if (!authfile && !ldap)
	{
		server_error(403, "Authentication information is not available",
			"NOT_AVAILABLE");
		return 1;
	}

	if (authfile && !(af = fopen(authfile, "r")))
	{
		server_error(403, "Authentication file is not available",
			"NOT_AVAILABLE");
		return 1;
	}

	if (authfile)
	{
		char		*p, line[LINEBUFSIZE];
		int		i = 1;

		if ((p = fgets(line, LINEBUFSIZE, af)))
			for (i = 0; *p; p++)
				if (':' == *p)
					i++;
		digest = i > 1;
		fclose(af);
	}
	else
		digest = 0;

	if (!authentication[0] ||
		(strncasecmp(authentication, "Basic", 5) &&
		 strncasecmp(authentication, "Digest", 6)))
	{
		asprintf(&errmsg,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
			"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
			"<head><title>Unauthorized</title></head>\n"
			"<body><h1>Unauthorized</h1><p>Your client does \n"
			"not understand %s authentication</p></body></html>\n",
			digest ? "digest" : "basic");
		if (headers)
		{
			secprintf("%s 401 Unauthorized\r\n", httpver);
#ifdef		HAVE_MD5
			if (digest)
			{
				secprintf("WWW-Authenticate: digest realm=\""
					REALM "\", nonce=\"%s\"%s\r\n",
					fresh_nonce(),
					rfc2617_digest
					 ? ", qop=\"auth\", algorithm=md5"
					 : "");
			}
			else
#endif		/* HAVE_MD5 */
				secputs("WWW-Authenticate: basic realm=\""
					REALM "\"\r\n");
			secprintf("Content-length: %zu\r\n", strlen(errmsg));
			stdheaders(1, 1, 1);
		}
		secputs(errmsg);
		free(errmsg);
		return(1);
	}
#ifdef		HAVE_MD5
	if ('d' == authentication[0] || 'D' == authentication[0])
	{
		if (!(rv = check_digest_auth(authfile)))
			return 0;
	}
	else
#endif		/* HAVE_MD5 */
	{
		if (!check_basic_auth(authfile, ldap))
			return 0;
	}

	asprintf(&errmsg,
		"\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
		"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
		"<head><title>Wrong password</title></head>\n"
		"<body><h1>Wrong user/password combination</h1>\n"
		"You don't have permission to view this page.\n"
		"</body></html>\n");
	if (headers)
	{
		secprintf("%s 401 Wrong user/password combination\r\n", httpver);
#ifdef		HAVE_MD5
		if (digest)
		{
			secprintf("WWW-Authenticate: digest realm=\""
				REALM "\", nonce=\"%s\"%s%s\r\n",
				fresh_nonce(),
				rfc2617_digest
				 ? ", qop=\"auth\", algorithm=md5"
				 : "",
				2 == rv ? ", stale=true" : "");
		}
		else
#endif		/* HAVE_MD5 */
			secputs("WWW-Authenticate: basic realm=\""
				REALM "\"\r\n");
		secprintf("Content-length: %zu\r\n", strlen(errmsg));
		stdheaders(1, 1, 1);
	}
	secputs(errmsg);
	free(errmsg);
	return(1);
}

void
initnonce()
{
	srandomdev();
	secret = random();
}

#ifdef		HAVE_MD5
static char *
fresh_nonce(void)
{
	static char	nonce[MAX_NONCE_LENGTH];
	char		bufhex[MD5_DIGEST_STRING_LENGTH];
	const long	ts = (long)time(NULL);
	char	*buf;
	size_t	len;

	len = asprintf(&buf, "%lx:%lu:%s", ts, secret, getenv("REMOTE_ADDR"));
	MD5Data((unsigned char *)buf, len, bufhex);
	free(buf);

	snprintf(nonce, MAX_NONCE_LENGTH, "%lx:%s", ts, bufhex);
	return nonce;
}

static int
valid_nonce(const char *nonce)
{
	char	bufhex[MD5_DIGEST_LENGTH];
	const char	*ptr;
	char	*buf;
	long	ts;
	int	len;

	if (!nonce)
		return 0;		/* invalid */
	if (!(ptr = strchr(nonce, ':')))
		return 0;
	ptr++;
	ts = strtol(nonce, NULL, 16);

	/* XXX: asprintf() seems buggy */
	buf = malloc(100);
	len = snprintf(buf, 100, "%lx:%lu:%s", ts, secret, getenv("REMOTE_ADDR"));
	MD5Data((unsigned char *)buf, len, bufhex);
	free(buf);

	if (strcmp(ptr, bufhex))
		return 0;

	/* fresh for 1 hour */
	return ts + 3600 > (long)time(NULL);
}
#endif		/* HAVE_MD5 */
