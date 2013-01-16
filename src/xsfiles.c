/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

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
#ifdef		HAVE_LIBUTIL_H
#include	<libutil.h>
#else		/* HAVE_LIBUTIL_H */
# ifdef		HAVE_UTIL_H
# include	<util.h>
# endif		/* HAVE_UTIL_H */
#endif		/* HAVE_LIBUTIL_H */

#include	"httpd.h"
#include	"htconfig.h"
#include	"httypes.h"
#include	"methods.h"
#include	"extra.h"
#include	"pcre.h"
#include	"authenticate.h"
#include	"xsfiles.h"
#include	"malloc.h"
#include	"modules.h"

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
mknewurl(const char * const old, const char * const new)
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
check_file_redirect(const char * const base, const char * const filename)
{
	int		fd;
	ssize_t		size;
	char		total[XS_PATH_MAX];
	xs_redirflags_t	flags = 0;

	if (!filename || !*filename)
		return false;

	/* Check for *.redir instructions */
	snprintf(total, XS_PATH_MAX, "%s%s.redir", base, filename);
	if ((fd = open(total, O_RDONLY, 0)) < 0)
	{
		snprintf(total, XS_PATH_MAX, "%s%s.Redir", base, filename);
		if ((fd = open(total, O_RDONLY, 0)) < 0)
			return false;
		flags &= redir_perm;
	}
	if ((size = read(fd, total, XS_PATH_MAX)) <= 0)
	{
		xserror(500, "Redirection filename error");
		close(fd);
		return true;
	}
	close(fd);

	char		*p;
	const char	*subst;

	total[size] = '\0';
	p = total;
	subst = strsep(&p, " \t\r\n");
	redirect(subst, flags & redir_env);
	return true;
}

bool
check_redirect(const char * const cffile, const char * const filename)
{
	char		*request;
	const char	*command;
	char	**argv = NULL;
	FILE	*fp;
	bool	guard = true;
	bool	exittrue = false;
	bool	exitfalse= false;
	ssize_t	ret;

	if (!(fp = fopen(cffile, "r")))
		/* no redir */
		return false;

	STRDUP(request, filename);

	while ((ret = fgetmfields(fp, &argv)) >= 0)
	{
		command = argv[0];

		/* skip comments and blank lines */
		if (!ret)
		{
			/* block reset */
			guard = true;
			continue;
		}

		if (!guard)
			/* continue */;

		/* use pcre matching */
		else if (!strcasecmp(command, "ifenv") && ret >= 3)
		{
			const char *		envvar = argv[1];
			const char * const	value = argv[2];

			if ('$' == *envvar)
				envvar++;
			if (!*envvar ||
					!(envvar = getenv(envvar)) ||
					(pcre_match(envvar, value) <= 0))
				/* no match -> skip block */
				guard = false;
		}
		else if (!strcasecmp(command, "ifnenv") && ret == 2)
		{
			if (getenv(argv[1]))
				/* no match -> skip block */
				guard = false;
		}
		else if (!strcasecmp(command, "pass") && ret == 1)
			exitfalse = true;
		else if (!strcasecmp(command, "pass") && ret >= 2)
		{
			if (pcre_match(request, argv[1]) > 0)
				exitfalse = true;
		}
		else if (!strcasecmp(command, "passexist"))
		{
			struct stat	statbuf;
			const char * const orig = getenv("SCRIPT_FILENAME");

			if (orig && !stat(orig, &statbuf))
				exitfalse = true;
		}
		else if (!strcasecmp(command, "redir") && ret >= 3)
		{
			const char	*newloc;
			char	*subst = pcre_subst(request, argv[1], argv[2]);

			if (subst && *subst)
			{
				newloc = mknewurl(request, subst);
				redirect(newloc, 'R' == command[0] ? redir_perm : 0);
				FREE(subst);
				exittrue = true;
			}
		}
		else if (!strcasecmp(command, "rewrite") && ret >= 3)
		{
			char	*subst = pcre_subst(request, argv[1], argv[2]);

			if (subst && *subst)
			{
				do_get(subst);
				FREE(subst);
				exittrue = true;
			}
		}
		else if (!strcasecmp(command, "forward") && ret >= 4)
		{
			/* old style argument parsing
			 * use new (2 args) syntax instead
			 */
			char	*subst = pcre_subst(request, argv[2], argv[3]);

			if (subst && *subst)
			{
				do_proxy(argv[1], subst);
				FREE(subst);
				exittrue = true;
			}
		}
		else if (!strcasecmp(command, "forward") && ret >= 3)
		{
			char	*subst = pcre_subst(request, argv[1], argv[2]);

			if (subst && *subst)
			{
				const char * const newloc =
					mknewurl(request, subst);
				do_proxy(NULL, newloc);
				FREE(subst);
				exittrue = true;
			}
		}
		else if (!strcasecmp(command, "error") &&
				ret >= 3 &&
				pcre_match(request, argv[2]) > 0)
		{
			const int	errcode = atoi(argv[1]);
			char	*args, *p;

			if (errcode < 400 || errcode >= 600)
				/* ignore */;
			else if (ret > 3)
			{
				/* Reconstruct args */
				size_t	sz = 0;
				int	i;

				for (i = 3; i < ret; i++)
					sz += strlen(argv[i]) + 1;

				MALLOC(args, char, sz);
				p = args;
				for (i = 3; i < ret; i++)
				{
					p = stpcpy(p, argv[i]);
					*p++ = ' ';
				}
				if (sz)
					p[-1] = '\0';
				xserror(errcode, "%s", args);
				FREE(args);
				exittrue = 1;
			}
			else
			{
				xserror(404, errcode == 404
					? "Requested URL not found"
					: "Access denied");
				exittrue = 1;
			}
		}
		else if (1 == ret)
			/* no command: redir to url */
		{
			const char * const newloc = mknewurl(request, command);

			redirect(newloc, redir_env);
			exittrue = true;
		}

		while (ret > 0)
		{
			ret--;
			FREE(argv[ret]);
		}
		FREE(argv);
		if (exittrue || exitfalse)
		{
			fclose(fp);
			return exittrue;
		}
	}
	fclose(fp);
	return false;
}

bool
check_allow_host(const char * const hostname, char * const pattern)
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
		struct	addrinfo	*res;
		const struct addrinfo	hints = {
			.ai_family = PF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
		};

		if (!cport && !getaddrinfo(NULL, pattern + 1, &hints, &res))
		{
			const struct sockaddr_in6 * const r6 = (void *)res->ai_addr;
			const struct sockaddr_in  * const r4 = (void *)res->ai_addr;
			cport = htons(res->ai_family == AF_INET6
				? r6->sin6_port
				: r4->sin_port);
			freeaddrinfo(res);
		}
		if (lport && cport == lport)
			return true; /* access granted */
	}
#endif		/* HAVE_GETADDRINFO */
	return false;
}

bool
check_noxs(const char * const cffile)
{
	FILE	*rfile;
	char	*allowhost;

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

	while ((allowhost = fparseln(rfile, NULL, NULL, NULL, FPARSEARG)))
	{
		if (check_allow_host(env.remote_addr, allowhost))
		{
			fclose(rfile);
			FREE(allowhost);
			return false; /* access granted */
		}

		FREE(allowhost);
	}

	fclose(rfile);
	server_error(403, "File is not available", "NOT_AVAILABLE");
	return true;
}

bool
check_xsconf(const char * const cffile, const char * const filename, const int depth, cf_values * const cfvalues)
{
	char	*line;
	char    **authfiles;
	size_t	num_authfiles = 0;
	bool	state = 0;
	bool	restrictcheck = 0, restrictallow = 0;
	bool	sslcheck = 0, sslallow = 0;
	FILE    *fp;

	authfiles = NULL;

	if (!(fp = fopen(cffile, "r")))
	{
		server_error(403, "Authentication file is not available",
			"NOT_AVAILABLE");
		return true; /* access denied */
	}

	while ((line = fparseln(fp, NULL, NULL, NULL, FPARSEARG)))
	{
		char    *p, *name, *value;

		if (!*line)
		{
			FREE(line);
			continue;
		}

		p = line;
		while ((name = strsep(&p, " \t\r\n")) && !*name)
			/* continue */;

		/* try to isolate a [url] section */
		if ('[' == name[0])
		{
			for (p = ++name; *p && *p != ']'; p++)
				/* skip */;
			if (!*p)
			{
				/* [ without ]; skip it */
				FREE(line);
				continue;
			}
			*p = '\0';

			p = name;
			while ((p = strchr(p, '/')))
			{
				*p++ = '\0';
				if (name[0] == '.' && !name[1])
				{
					if (depth)
					{
						FREE(line);
						continue;
					}
				}
				else if (!env.request_method ||
					strcasecmp(name, env.request_method))
				{
					FREE(line);
					continue;
				}
				name = p;
			}
			/* try simple matching */
			state = !strcmp(name, "*") ||
				fnmatch(name, filename, 0) != FNM_NOMATCH;
			FREE(line);
			continue;
		}

		/* ignore anything else if no match */
		if (!state)
		{
			FREE(line);
			continue;
		}

		/* strip leading/trailing whitespace from value */
		for ( ; isspace(*p); p++)
			/* do nothing */;
		value = p;
		p = strchr(value, '\0');
		while (isspace(*--p))
			*p = '\0';

		if (!value || !*value)
		{
			FREE(line);
			continue;
		}

		/* AuthFilename => $file does .xsauth-type authentication */
		if (!strcasecmp(name, "AuthFilename") ||
			!strcasecmp(name, "AuthFile") ||
			!strcasecmp(name, "AuthFiles"))
		{
			const char	* const slash = strrchr(cffile, '/');
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
					ASPRINTF(&temp, "%.*s/%s",
						(int)(slash - cffile),
						cffile, authfiles[i]);
					FREE(authfiles[i]);
					authfiles[i] = temp;
				}
		}
		else if (!strcasecmp(name, "Restrict"))
		{
			char		**restrictions = NULL;
			size_t		i, asz;

			restrictcheck = true;
			asz = string_to_arrayp(value, &restrictions);

			for (i = 0; i < asz; i++)
				restrictallow |= check_allow_host
					(env.remote_addr, restrictions[i]);
			free_string_array(restrictions, asz);
		}
		else if (!strcasecmp(name, "MimeType"))
			STRDUP(cfvalues->mimetype, value);
		else if (!strcasecmp(name, "Execute"))
			STRDUP(cfvalues->scripttype, value);
		else if (!strcasecmp(name, "Charset"))
			STRDUP(cfvalues->charset, value);
		else if (!strcasecmp(name, "Language"))
			STRDUP(cfvalues->language, value);
		else if (!strcasecmp(name, "IndexFile"))
			STRDUP(cfvalues->indexfile, value);
		else if (!strcasecmp(name, "p3pReference"))
			STRDUP(cfvalues->p3pref, value);
		else if (!strcasecmp(name, "p3pCompactPolicy"))
			STRDUP(cfvalues->p3pcp, value);
		else if (!strcasecmp(name, "DeleteScript"))
			STRDUP(cfvalues->delscript, value);
		else if (!strcasecmp(name, "PutScript"))
			STRDUP(cfvalues->putscript, value);
		else if (!strcasecmp(name, "ScriptTimeout"))
			config.scripttimeout = strtoul(value, NULL, 10);
		else if (!strcasecmp(name, "NoPrivs"))
			cfvalues->noprivs = !strcasecmp("true", value);

		/* SSL client cert options */
		else if (!strcasecmp(name, "SSLSubjectMatch"))
		{
			const char * const subject = getenv("SSL_CLIENT_S_DN");
			const int	smatch =
				subject ? pcre_match(subject, value) : -1;

			sslcheck = true;
			if (smatch < 0)
				sslallow = false;
			else
				sslallow |= smatch;
		}
		else if (!strcasecmp(name, "SSLIssuerMatch"))
		{
			const char * const issuer = getenv("SSL_CLIENT_I_DN");
			const int smatch =
				issuer ? pcre_match(issuer, value) : -1;

			sslcheck = true;
			if (smatch < 0)
				sslallow = false;
			else
				sslallow |= smatch;
		}
		else
			/* Check modules for configuration directives */
			for (struct module *mod, **mods = modules;
					(mod = *mods); mods++)
				if (mod->config_local)
					mod->config_local(name, value);

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
			if (check_auth(authfiles[i], true))
				/* access granted */
				break;
		}
		else if (!check_auth(authfiles[i], false))
		{
			/* a 401 response has been sent */
			free_string_array(authfiles, num_authfiles);
			return true;
		}
	}
	free_string_array(authfiles, num_authfiles);

	(void)depth;
	return false;
}

void
free_xsconf(cf_values * const cfvalues)
{
	if (cfvalues->charset)
		FREE(cfvalues->charset);
	if (cfvalues->mimetype)
		FREE(cfvalues->mimetype);
	if (cfvalues->scripttype)
		FREE(cfvalues->scripttype);
	if (cfvalues->language)
		FREE(cfvalues->language);
	if (cfvalues->encoding)
		FREE(cfvalues->encoding);
	if (cfvalues->indexfile)
		FREE(cfvalues->indexfile);
	if (cfvalues->p3pref)
		FREE(cfvalues->p3pref);
	if (cfvalues->p3pcp)
		FREE(cfvalues->p3pcp);
	if (cfvalues->putscript)
		FREE(cfvalues->putscript);
}
