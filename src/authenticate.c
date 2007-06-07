/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */
/* $Id: authenticate.c,v 1.12 2007/03/29 15:20:36 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<unistd.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"decode.h"
#include	"ssl.h"
#include	"authenticate.h"
#include	"ldap.h"
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

char		authentication[MYBUFSIZ];
unsigned long int	secret;

static int	get_crypted_password(const char *, const char *, char **, char **);
static int	check_basic_auth(const char *authfile, const struct ldap_auth *);
#ifdef		HAVE_MD5
static int	check_digest_auth(const char *authfile);
static char	*get_auth_argument(const char *key, char *line, size_t len);
static void	fresh_nonce(char *nonce);
static int	valid_nonce(char *nonce);
#endif		/* HAVE_MD5 */

/* returns malloc()ed data! */
static int
get_crypted_password(const char *authfile, const char *user, char **passwd, char **hash)
{
	char	line[LINEBUFSIZE];
	char	*lpass, *lhash, *eol;
	FILE	*af;

	if (!(af = fopen(authfile, "r")))
		return 0;

	if (passwd)
		*passwd = NULL;
	if (hash)
		*hash = NULL;

	while (fgets(line, LINEBUFSIZE, af))
	{
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
	if (!get_crypted_password(authfile, search, &passwd, NULL) || !passwd)
	{
		free(line);
		return 1;
	}

	if (!strcmp(passwd, crypt(find, passwd)))
	{
		free(line);
		free(passwd);
		/* allow access */
		return 0;
	}
	else
	{
		free(line);
		free(passwd);
		return 1;
	}
}

#ifdef		HAVE_MD5
static char *
get_auth_argument(const char *key, char *line, size_t len)
{
	char	*p, *q;
	char	substr[MYBUFSIZ];

	snprintf(substr, MYBUFSIZ, "%s=%c", key, '"');

	if ((p = memmem(line, len, key, strlen(key))) &&
			(q = strchr(p += strlen(substr), '"')))
		*q = '\0';
	else
		return NULL;

	return p;
}

static int
check_digest_auth(const char *authfile)
{
	char		*user, *passwd, *realm, *nonce, *uri, *response,
			*a2, *digplain,
			*ha1, ha2[MD5_DIGEST_STRING_LENGTH],
			digest[MD5_DIGEST_STRING_LENGTH],
			line[LINEBUFSIZE];
	size_t		len;

	/* digest auth, rfc 2069 */
	len = strlcpy(line, authentication, LINEBUFSIZE);
	if (len > LINEBUFSIZE)
		len = LINEBUFSIZE;

	user	= get_auth_argument("username",	line, len);
	realm	= get_auth_argument("realm",	line, len);
	nonce	= get_auth_argument("nonce",	line, len);
	uri	= get_auth_argument("uri",	line, len);
	response= get_auth_argument("response",	line, len);

	if (!user || !realm || !nonce || !uri || !response)
		return 1; /* fail */
	if (!get_crypted_password(authfile, user, &passwd, &ha1) || !passwd)
	{
		return 1; /* not found */
	}

	if (!ha1)
	{
		free(passwd);
		return 1;
	}

	/* obtain h(a1) from file */
	if (strlen(ha1) > MD5_DIGEST_STRING_LENGTH)
		return 1; /* no valid hash */

	/* calculate h(a2) */
	len = asprintf(&a2, "%s:%s", getenv("REQUEST_METHOD"), uri);
	MD5Data((const unsigned char *)a2, len, ha2);
	free(a2);

	/* calculate digest from h(a1) and h(a2) */
	len = asprintf(&digplain, "%s:%s:%s", ha1, nonce, ha2);
	MD5Data((const unsigned char *)digplain, len, digest);
	free(digplain);

	if (strcmp(response, digest))
		return 1; /* no match */

	if (!valid_nonce(nonce))
	{
		fprintf(stderr, "401: Valid id with invalid nonce %s\n", nonce);
		return 1; /* invalid */
	}

	setenv("AUTH_TYPE", "Digest", 1);
	setenv("REMOTE_USER", user, 1);

	return 0;
}
#endif		/* HAVE_MD5 */

int
check_auth(const char *authfile, const struct ldap_auth *ldap)
{
	char		*p, line[LINEBUFSIZE], errmsg[10240],
			nonce[MAX_NONCE_LENGTH];
	int		i = 1, digest;
	FILE		*af;

	if (!authfile && !ldap)
	{
		server_error("403 Authentication information is not available",
			"NOT_AVAILABLE");
		return 1;
	}

	if (authfile && !(af = fopen(authfile, "r")))
	{
		server_error("403 Authentication file is not available",
			"NOT_AVAILABLE");
		return 1;
	}

	if (authfile)
	{
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

		snprintf(errmsg, sizeof(errmsg),
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
				fresh_nonce(nonce);
				secprintf("WWW-authenticate: digest realm=\""
					REALM "\" nonce=\"%s\"\r\n", nonce);
			}
			else
#endif		/* HAVE_MD5 */
				secputs("WWW-authenticate: basic realm=\""
					REALM "\"\r\n");
			secprintf("Content-length: %zu\r\n", strlen(errmsg));
			stdheaders(1, 1, 1);
		}
		secputs(errmsg);
		return(1);
	}
#ifdef		HAVE_MD5
	if ('d' == authentication[0] || 'D' == authentication[0])
	{
		if (!check_digest_auth(authfile))
			return 0;
	}
	else
#endif		/* HAVE_MD5 */
	{
		if (!check_basic_auth(authfile, ldap))
			return 0;
	}

	snprintf(errmsg, sizeof(errmsg),
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
			fresh_nonce(nonce);
			secprintf("WWW-authenticate: digest realm=\""
				REALM "\" nonce=\"%s\"\r\n", nonce);
		}
		else
#endif		/* HAVE_MD5 */
			secputs("WWW-authenticate: basic realm=\""
				REALM "\"\r\n");
		secprintf("Content-length: %zu\r\n", strlen(errmsg));
		stdheaders(1, 1, 1);
	}
	secputs(errmsg);
	return(1);
}

void
initnonce()
{
	srandom((unsigned long)time(NULL));
	secret = random();
}

#ifdef		HAVE_MD5
static void
fresh_nonce(char *nonce)
{
	long	ts = (long)time(NULL);
	char	*ip, *buf;
	char	bufhex[MD5_DIGEST_STRING_LENGTH];
	size_t	len;

	ip = getenv("REMOTE_ADDR");
	len = asprintf(&buf, "%lx:%lu:%s", ts, secret, ip);
	MD5Data((const unsigned char *)buf, len, bufhex);
	free(buf);

	snprintf(nonce, MAX_NONCE_LENGTH, "%lx:%s", ts, bufhex);
}

static int
valid_nonce(char *nonce)
{
	long	ts;
	time_t	tsnow;
	char	*ip, *buf, *ptr;
	char	bufhex[MD5_DIGEST_LENGTH];
	size_t	len;

	if (!nonce)
		return 0;		/* invalid */
	if (!(ptr = strchr(nonce, ':')))
		return 0;
	*ptr++ = '\0';
	ts = strtol(nonce, NULL, 16);
	ip = getenv("REMOTE_ADDR");

	len = asprintf(&buf, "%lx:%lu:%s", ts, secret, ip);
	MD5Data((const unsigned char *)buf, len, bufhex);
	free(buf);

	if (strcmp(ptr, bufhex))
		return 0;

	time((time_t *)&tsnow);

	/* fresh for 1 hour */
	return ts + 3600 > (long)tsnow;
}
#endif		/* HAVE_MD5 */
