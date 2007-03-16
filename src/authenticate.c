/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */
/* $Id: authenticate.c,v 1.6 2007/03/16 21:53:51 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>

#include	"httpd.h"
#include	"authenticate.h"
#include	"ssl.h"
#include	"decode.h"
#include	"xscrypt.h"

char		authentication[MYBUFSIZ];
unsigned long int	secret;

static int	get_crypted_password(FILE *, const char *, char **, char **);
static int	check_basic_auth(FILE *authfile);
#ifdef		HAVE_MD5
static int	check_digest_auth(FILE *authfile);
static char	*get_auth_argument(const char *key, char *line, size_t len);
static void	fresh_nonce(char *nonce);
static int	valid_nonce(char *nonce);
#endif		/* HAVE_MD5 */

/* returns malloc()ed data! */
static int
get_crypted_password(FILE *authfile, const char *user, char **passwd, char **hash)
{
	char	line[LINEBUFSIZE];
	char	*lpass, *lhash, *eol;

	if (passwd)
		*passwd = NULL;
	if (hash)
		*hash = NULL;

	while (fgets(line, LINEBUFSIZE, authfile))
	{
		if (strncmp(line + 1, user, strlen(user)) ||
				line[strlen(user)+1] != ':')
			continue;

		if ((lpass = strchr(line, ':')))
			lpass++;
		else
			return 0;
		if ((lhash = strchr(lpass, ':')))
			*lhash++ = '\0';
		if ((eol = strchr(lhash ? lhash : lpass, '\r')) ||
				(eol = strchr(lhash ? lhash : lpass, '\n')))
			*eol = '\0';

		if (passwd)
			*passwd = strdup(lpass);
		if (hash)
			*hash = lhash ? strdup(lhash) : NULL;
		return 1; /* found! */
	}
	return 0;
}

static int
check_basic_auth(FILE *authfile)
{
	char		*search, line[LINEBUFSIZE], *passwd, *find;

	/* basic auth */
	strlcpy(line, authentication, sizeof(LINEBUFSIZE));
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
		if (!check_auth_ldap(authfile, search, find))
		{
			return(0);
		}
		rewind (authfile);
#endif /* AUTH_LDAP */

		snprintf(line, LINEBUFSIZE, "%s:%s\n", search, xs_encrypt(find));
	}
	if (!get_crypted_password(authfile, search, &passwd, NULL) || !passwd)
		return 1;

	if (!strcmp(passwd, xs_encrypt(find)))
	{
		free(passwd);
		/* allow access */
		return 0;
	}
	else
	{
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
check_digest_auth(FILE *authfile)
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
check_auth(FILE *authfile)
{
	char		*p, line[LINEBUFSIZE], errmsg[10240],
			nonce[MAX_NONCE_LENGTH];
	int		i = 1, digest;

	if ((p = fgets(line, LINEBUFSIZE, authfile)))
		for (i = 0; *p; p++)
			if (':' == *p)
				i++;
	digest = i > 1;

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
		fclose(authfile);
		return(1);
	}
#ifdef		HAVE_MD5
	if ('d' == authentication[0] || 'D' == authentication[0])
	{
		if (!check_digest_auth(authfile))
		{
			fclose(authfile);
			return 0;
		}
	}
	else
#endif		/* HAVE_MD5 */
	{
		if (!check_basic_auth(authfile))
		{
			fclose(authfile);
			return 0;
		}
	}
	fclose(authfile);

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
	srandom((unsigned int)time(NULL));
	secret = random();
}

#ifdef		HAVE_MD5
static void
fresh_nonce(char *nonce)
{
	int	ts = (int)time(NULL);
	char	*ip, *buf;
	char	bufhex[MD5_DIGEST_STRING_LENGTH];
	size_t	len;

	ip = getenv("REMOTE_ADDR");
	len = asprintf(&buf, "%d:%lu:%s", ts, secret, ip);
	MD5Data((const unsigned char *)buf, len, bufhex);
	free(buf);

	snprintf(nonce, MAX_NONCE_LENGTH, "%d:%s", ts, bufhex);
}

static int
valid_nonce(char *nonce)
{
	int	ts, tsnow;
	char	*ip, *buf, *ptr;
	char	bufhex[MD5_DIGEST_LENGTH];
	size_t	len;

	if (!nonce)
		return 0;		/* invalid */
	ts = atoi(nonce);
	ip = getenv("REMOTE_ADDR");

	len = asprintf(&buf, "%d:%lu:%s", ts, secret, ip);
	MD5Data((const unsigned char *)buf, len, bufhex);
	free(buf);

	if (!(ptr = strchr(nonce, ':')))
		return 0;
	if (strcmp(++ptr, bufhex))
		return 0;

	time((time_t *)&tsnow);

	/* fresh for 1 hour */
	return ts + 3600 > tsnow;
}
#endif		/* HAVE_MD5 */
