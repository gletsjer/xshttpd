/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<netdb.h>

#include	<fcntl.h>
#include	<stdio.h>
#include	<errno.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<string.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<fnmatch.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"methods.h"
#include	"extra.h"
#include	"ldap.h"
#include	"pcre.h"
#include	"authenticate.h"
#include	"xsfiles.h"
#include	"malloc.h"

#ifdef		HAVE_STRUCT_IN6_ADDR
# ifndef	IN6_ARE_MASKED_ADDR_EQUAL
#  define IN6_ARE_MASKED_ADDR_EQUAL(d, a, m)      (       \
	(((d)->s6_addr32[0] ^ (a)->s6_addr32[0]) & (m)->s6_addr32[0]) == 0 && \
	(((d)->s6_addr32[1] ^ (a)->s6_addr32[1]) & (m)->s6_addr32[1]) == 0 && \
	(((d)->s6_addr32[2] ^ (a)->s6_addr32[2]) & (m)->s6_addr32[2]) == 0 && \
	(((d)->s6_addr32[3] ^ (a)->s6_addr32[3]) & (m)->s6_addr32[3]) == 0 )
# endif		/* IN6_ARE_MASKED_ADDR_EQUAL */
#endif		/* HAVE_STRUCT_IN6_ADDR */

static char *	mknewurl		(const char *, const char *);
#ifdef		HAVE_STRUCT_IN6_ADDR
static void	v6masktonum		(unsigned int, struct in6_addr *);
#endif		/* HAVE_STRUCT_IN6_ADDR */

static char    *
mknewurl(const char *old, const char *new)
{
	static char	result[XS_PATH_MAX];
	char		*p;

	result[0] = '\0';
	if (!new)
		return result;

	if ((p = strstr(new, "://")))
	{
		strlcpy(result, new, XS_PATH_MAX);
		return result;
	}
	/* add protocol and hostname */
	if (cursock->usessl)
		strlcpy(result, "https://", XS_PATH_MAX);
	else
		strlcpy(result, "http://", XS_PATH_MAX);
	if ((p = getenv("HTTP_HOST")))
		strlcat(result, p, XS_PATH_MAX);
	else
		strlcat(result, current->hostname, XS_PATH_MAX);
	if (new[0] != '/')
	{
		/* add path */
		if (strchr(old, '/'))
			strlcat(result, old, XS_PATH_MAX);
		p = strrchr(result, '/');
		if (p && p[1])
			p[1] = '\0';
	}
	strlcat(result, new, XS_PATH_MAX);
	return result;
}

#ifdef		HAVE_STRUCT_IN6_ADDR
static	void
v6masktonum(unsigned int mask, struct in6_addr *addr6)
{
	unsigned int		x, y, z;

	for (x = 0; x < 4; x++)
		addr6->s6_addr32[x] = 0;

	y = 0;
	z = 0;
	for (x = 0; x < mask; x++)
	{
		addr6->s6_addr[y] |= (1 << (7 - z));
		z++;
		if (z == 8)
		{
			z = 0;
			y++;
		}
	}
}
#endif		/* HAVE_STRUCT_IN6_ADDR */

bool
check_file_redirect(const char *base, const char *filename)
{
	int	fd, size;
	bool	permanent = false;
	char	total[XS_PATH_MAX];

	if (!filename || !*filename)
		return false;

	/* Check for *.redir instructions */
	snprintf(total, XS_PATH_MAX, "%s%s.redir", base, filename);
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		snprintf(total, XS_PATH_MAX, "%s%s.Redir", base, filename);
		if ((fd = open(total, O_RDONLY, 0)) < 0)
			return false;
		permanent = true;
	}
	if ((size = read(fd, total, XS_PATH_MAX)) <= 0)
	{
		xserror(500, "Redirection filename error");
		close(fd);
		return true;
	}
	close(fd);

	char	*p, *subst;
	total[size] = '\0';
	p = total;
	subst = strsep(&p, " \t\r\n");
	redirect(subst, permanent, true);
	return true;
}

bool
check_redirect(const char *cffile, const char *filename)
{
	char	line[XS_PATH_MAX], request[XS_PATH_MAX];
	FILE	*fp;

	if (!(fp = fopen(cffile, "r")))
		/* no redir */
		return false;

	strlcpy(request, filename, XS_PATH_MAX);

	while (fgets(line, XS_PATH_MAX, fp))
	{
		char	*p, *command;
		char	*subst, *orig, *repl, *newloc, *host;

		p = line;
		while ((command = strsep(&p, " \t\r\n")) && !*command)
			/* continue */;

		/* skip comments and blank lines */
		if (!command || !*command || '#' == *command)
			continue;

		/* use pcre matching */
		if (!strcasecmp(command, "pass"))
		{
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			if (pcre_match(request, orig) > 0)
			{
				fclose(fp);
				return false;
			}
		}
		else if (!strcasecmp(command, "passexist"))
		{
			struct stat	statbuf;

			if ((orig = getenv("SCRIPT_FILENAME")) &&
				!stat(orig, &statbuf))
			{
				return false;
			}
		}
		else if (!strcasecmp(command, "redir"))
		{
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			while ((repl = strsep(&p, " \t\r\n")) && !*repl)
				/* continue */;
			if ((subst = pcre_subst(request, orig, repl)) &&
					*subst)
			{
				newloc = mknewurl(request, subst);
				redirect(newloc, 'R' == command[0], 0);
				free(subst);
				fclose(fp);
				return true;
			}
		}
		else if (!strcasecmp(command, "rewrite"))
		{
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			while ((repl = strsep(&p, " \t\r\n")) && !*repl)
				/* continue */;
			if ((subst = pcre_subst(request, orig, repl)) &&
					*subst)
			{
				do_get(subst);
				free(subst);
				fclose(fp);
				return true;
			}
		}
		else if (!strcasecmp(command, "forward"))
		{
			while ((host = strsep(&p, " \t\r\n")) && !*host)
				/* continue */;
			while ((orig = strsep(&p, " \t\r\n")) && !*orig)
				/* continue */;
			while ((repl = strsep(&p, " \t\r\n")) && !*repl)
				/* continue */;
			if ((subst = pcre_subst(request, orig, repl)) &&
					*subst)
			{
				do_proxy(host, subst);
				free(subst);
				fclose(fp);
				return true;
			}
		}
		else /* no command: redir to url */
		{
			newloc = mknewurl(request, command);
			redirect(newloc, false, true);
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

bool
check_allow_host(const char *hostname, char *pattern)
{
	char	*slash;

	/* return 1 if pattern matches - i.e. access granted */
	if (!hostname || !pattern || !*hostname || !*pattern)
		return false;
	
	/* substring match */
	if (!strncmp(hostname, pattern, strlen(pattern)))
		return true;

	/* allow host if remote_addr matches CIDR subnet in file */
	if ((slash = strchr(pattern, '/')) &&
		strchr(hostname, '.') &&
		strchr(pattern, '.'))
	{
		struct	in_addr		allow, remote;
		unsigned int		subnet;

		*slash = '\0';
		if ((subnet = strtoul(slash + 1, NULL, 10)) > 32)
			subnet = 32;
		inet_aton(hostname, &remote);
		inet_aton(pattern, &allow);

#define	IPMASK(addr, sub) (addr.s_addr & htonl(~((1 << (32 - (sub))) - 1)))
		if (IPMASK(remote, subnet) == IPMASK(allow, subnet))
			return true;
	}
#ifdef		HAVE_STRUCT_IN6_ADDR
	if ((slash = strchr(pattern, '/')) &&
		strchr(pattern, ':') &&
		strchr(hostname, ':'))
	{
		struct	in6_addr	allow, remote, mask;
		unsigned int		subnet;

		*slash = '\0';
		if ((subnet = strtoul(slash + 1, NULL, 10)) > 128)
			subnet = 128;
		inet_pton(AF_INET6, hostname, &remote);
		inet_pton(AF_INET6, pattern, &allow);
		v6masktonum(subnet, &mask);
		if (IN6_ARE_MASKED_ADDR_EQUAL(&remote, &allow, &mask))
			return true;
	}
#endif		/* HAVE_STRUCT_IN6_ADDR */

	/* allow any host if the local port matches :port in .noxs */
#ifdef		HAVE_GETADDRINFO
	if (':' == pattern[0])
	{
		in_port_t	cport = strtoul(hostname + 1, NULL, 10);
		in_port_t	lport = strtoul(getenv("SERVER_PORT"), NULL, 10);
		struct	addrinfo	hints, *res;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if (!cport && !getaddrinfo(NULL, pattern + 1, &hints, &res))
		{
			cport = htons(res->ai_family == AF_INET6
				? ((struct sockaddr_in6 *)res->ai_addr)->sin6_port
				: ((struct sockaddr_in *)res->ai_addr)->sin_port);
			freeaddrinfo(res);
		}
		if (lport && cport == lport)
			return true; /* access granted */
	}
#endif		/* HAVE_GETADDRINFO */
	return false;
}

bool
check_noxs(const char *cffile)
{
	char	allowhost[256];
	FILE	*rfile;

	if (!(rfile = fopen(cffile, "r")))
	{
		server_error(403, "Authentication file is not available",
			"NOT_AVAILABLE");
		return true; /* access denied */
	}

	if (!env.remote_addr)
	{
		server_error(403, "File is not available", "NOT_AVAILABLE");
		return true; /* access denied */
	}

	while (fgets(allowhost, 256, rfile))
	{
		if (strlen(allowhost) &&
			allowhost[strlen(allowhost) - 1] == '\n')
		    allowhost[strlen(allowhost) - 1] = '\0';

		if (!allowhost[0] || '#' == allowhost[0])
			continue;

		if (check_allow_host(env.remote_addr, allowhost))
		{
			fclose(rfile);
			return false; /* access granted */
		}
	}

	fclose(rfile);
	server_error(403, "File is not available", "NOT_AVAILABLE");
	return true;
}

bool
check_xsconf(const char *cffile, const char *filename, cf_values *cfvalues)
{
	char	line[LINEBUFSIZE];
	char    **authfiles;
	size_t	num_authfiles = 0;
	bool	state = 0;
	bool	restrictcheck = 0, restrictallow = 0;
	bool	sslcheck = 0, sslallow = 0;
	FILE    *fp;
	struct ldap_auth	ldap;

	authfiles = NULL;
	memset(&ldap, 0, sizeof(ldap));

	if (!(fp = fopen(cffile, "r")))
	{
		server_error(403, "Authentication file is not available",
			"NOT_AVAILABLE");
		return true; /* access denied */
	}

	while (fgets(line, LINEBUFSIZE, fp))
	{
		char    *p, *name, *value;

		p = line;
		while ((name = strsep(&p, " \t\r\n")) && !*name)
			/* continue */;

		/* skip comments and blank lines */
		if (!name || !*name || '#' == *name)
			continue;

		/* try to isolate a [url] section */
		if ('[' == name[0])
		{
			for (p = ++name; *p && *p != ']'; p++)
				/* skip */;
			if (!*p)
				/* [ without ]; skip it */
				continue;
			*p = '\0';

			if ((p = strchr(name, '/')))
			{
				*p++ = '\0';
				if (!env.request_method ||
					strcasecmp(name, env.request_method))
					continue;
				name = p;
			}
			/* try simple matching */
			state = !strcmp(name, "*") ||
				fnmatch(name, filename, 0) != FNM_NOMATCH;
			continue;
		}

		/* ignore anything else if no match */
		if (!state)
			continue;

		/* strip leading/trailing whitespace from value */
		for ( ; isspace(*p); p++)
			/* do nothing */;
		value = p;
		if ((p = strchr(value, '#')))
			*p = '\0';
		else
			p = strchr(value, '\0');
		while (isspace(*--p))
			*p = '\0';

		if (!value || !*value)
			continue;

		/* AuthFilename => $file does .xsauth-type authentication */
		if (!strcasecmp(name, "AuthFilename") ||
			!strcasecmp(name, "AuthFile") ||
			!strcasecmp(name, "AuthFiles"))
		{
			const char	*slash = strrchr(cffile, '/');
			char		*temp;

			if (num_authfiles)
				/* ignore previous lines */
				free_string_array(authfiles, num_authfiles);
			num_authfiles = string_to_arrayp(value, &authfiles);

			for (size_t i = 0; i < num_authfiles; i++)
				if (slash && authfiles[i] &&
					authfiles[i][0] != '/')
				{
					temp = NULL;
					asprintf(&temp, "%.*s/%s",
						(int)(slash - cffile),
						cffile, authfiles[i]);
					free(authfiles[i]);
					authfiles[i] = temp;
				}
		}
		else if (!strcasecmp(name, "Restrict"))
		{
			char		**restrictions = NULL;
			size_t		i, sz;

			restrictcheck = true;
			sz = string_to_arrayp(value, &restrictions);

			for (i = 0; i < sz; i++)
				restrictallow |= check_allow_host
					(env.remote_addr, restrictions[i]);
			free_string_array(restrictions, sz);
		}
		else if (!strcasecmp(name, "MimeType"))
			cfvalues->mimetype = strdup(value);
		else if (!strcasecmp(name, "Execute"))
			cfvalues->scripttype = strdup(value);
		else if (!strcasecmp(name, "Charset"))
			cfvalues->charset = strdup(value);
		else if (!strcasecmp(name, "Language"))
			cfvalues->language = strdup(value);
		else if (!strcasecmp(name, "IndexFile"))
			cfvalues->indexfile = strdup(value);
		else if (!strcasecmp(name, "p3pReference"))
			cfvalues->p3pref = strdup(value);
		else if (!strcasecmp(name, "p3pCompactPolicy"))
			cfvalues->p3pcp = strdup(value);
		else if (!strcasecmp(name, "DeleteScript"))
			cfvalues->delscript = strdup(value);
		else if (!strcasecmp(name, "PutScript"))
			cfvalues->putscript = strdup(value);
		else if (!strcasecmp(name, "ScriptTimeout"))
			config.scripttimeout = strtoul(value, NULL, 10);

		/* ldap options */
		else if (!strcasecmp(name, "LdapHost"))
		{
			if (ldap.uri)
				free(ldap.uri);
			asprintf(&ldap.uri, "ldap://%s", value);
		}
		else if (!strcasecmp(name, "LdapURI"))
		{
			if (ldap.uri)
				free(ldap.uri);
			ldap.uri = strdup(value);
		}
		else if (!strcasecmp(name, "LdapAttr"))
		{
			if (ldap.attr)
				free(ldap.attr);
			ldap.attr = strdup(value);
		}
		else if (!strcasecmp(name, "LdapDN"))
		{
			if (ldap.dn)
				free(ldap.dn);
			ldap.dn = strdup(value);
		}
		else if (!strcasecmp(name, "LdapVersion"))
			ldap.version = strtoul(value, NULL, 10);
		else if (!strcasecmp(name, "LdapGroups"))
		{
			if (ldap.groups)
				free(ldap.groups);
			ldap.groups = strdup(value);
		}

		/* SSL client cert options */
		else if (!strcasecmp(name, "SSLSubjectMatch"))
		{
			int	smatch;
			char	*subject = getenv("SSL_CLIENT_S_DN");

			sslcheck = true;
			smatch = subject ? pcre_match(subject, value) : -1;
			if (smatch < 0)
				sslallow = false;
			else
				sslallow |= smatch;
		}
		else if (!strcasecmp(name, "SSLIssuerMatch"))
		{
			int	smatch;
			char	*issuer = getenv("SSL_CLIENT_I_DN");

			sslcheck = true;
			smatch = issuer ? pcre_match(issuer, value) : -1;
			if (smatch < 0)
				sslallow = false;
			else
				sslallow |= smatch;
		}

		/* ... and much more ... */
	}

	fclose(fp);
	if ((restrictcheck && !restrictallow) ||
		(sslcheck && !sslallow))
	{
		free_string_array(authfiles, num_authfiles);
		server_error(403, "File is not available", "NOT_AVAILABLE");
		return true;
	}
	/* return err if authentication fails */
	for (size_t i = 0; i < num_authfiles; i++)
	{
		if (i + 1 < num_authfiles)
		{
			/* suppress errors from check_auth() */
			if (check_auth(authfiles[i], NULL, true))
				/* access granted */
				break;
		}
		else if (!check_auth(authfiles[i], NULL, false))
		{
			/* a 401 response has been sent */
			free_string_array(authfiles, num_authfiles);
			return true;
		}
	}
	free_string_array(authfiles, num_authfiles);

	if (ldap.dn && !check_auth(NULL, &ldap, false))
		/* a 401 response has been sent */
		return true;

	return false;
}

void
free_xsconf(cf_values *cfvalues)
{
	if (cfvalues->charset)
		free(cfvalues->charset);
	if (cfvalues->mimetype)
		free(cfvalues->mimetype);
	if (cfvalues->scripttype)
		free(cfvalues->scripttype);
	if (cfvalues->language)
		free(cfvalues->language);
	if (cfvalues->encoding)
		free(cfvalues->encoding);
	if (cfvalues->indexfile)
		free(cfvalues->indexfile);
	if (cfvalues->p3pref)
		free(cfvalues->p3pref);
	if (cfvalues->p3pcp)
		free(cfvalues->p3pcp);
	if (cfvalues->putscript)
		free(cfvalues->putscript);
}
