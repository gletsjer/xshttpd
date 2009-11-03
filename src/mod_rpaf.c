/* Copyright (C) 2009 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<unistd.h>

#include	"httypes.h"
#include	"malloc.h"
#include	"modules.h"
#include	"constants.h"
#include	"extra.h"

char		**rpafproxyips = NULL;
char		*rpafheader = NULL;
size_t		rpafproxyipnum = 0;

bool	rpaf	(const char *, const char *);
bool	rpaf_config(const char *, const char *);
bool	rpaf_open	(void);

bool
rpaf(const char *filename, const char *headers)
{
	size_t		sz, len;
	char		*clientip, *remoteaddr;

	if (!rpafheader)
		return false;

	/* Check if connection originates from listed proxy */
	remoteaddr = getenv("REMOTE_ADDR");
	for (sz = 0; sz < rpafproxyipnum; sz++)
		if (!strcmp(remoteaddr, rpafproxyips[sz]))
			break;

	if (sz == rpafproxyipnum)
		return false;

	/* Check presense of a Client-IP header */
	if ((clientip = strcasestr(headers, rpafheader)) &&
			(clientip == headers || clientip[-1] == '\n') &&
			(clientip[strlen(rpafheader)] == ':'))
		clientip += strlen(rpafheader) + 2;
	else
		return false;

	/* Replace REMOTE_ADDR by Client-IP address */
	len = strspn(clientip, "0123456789abcdef:.");
	clientip = strndup(clientip, len);

	setenv("PROXY_ADDR", getenv("REMOTE_ADDR"), 1);
	setenv("PROXY_HOST", getenv("REMOTE_HOST"), 1);
	setenv("REMOTE_ADDR", clientip, 1);
	setenv("REMOTE_HOST", clientip, 1);
	(void) filename;
	return true;
}

bool
rpaf_config(const char *name, const char *value)
{
	if (!name && !value)
	{
		if (rpafproxyips)
		{
			for (size_t sz = 0; sz < rpafproxyipnum; sz++)
				FREE(rpafproxyips[sz]);
			FREE(rpafproxyips);
			rpafproxyipnum = 0;
		}
		if (rpafheader)
			FREE(rpafheader);
		STRDUP(rpafheader, "Client-IP");
	}
	else if (!strcasecmp(name, "RpafProxyIPs"))
	{
		size_t		i = 0;
		const char	*start;
		const char	*p;
		bool		ws, ows;

		/* Count elements */
		ows = true;
		rpafproxyipnum = 0;
		for (p = value; *p; p++)
		{
			ws = (*p == ',' || *p == ' ' || *p == '\t');
			if (ows && !ws)
				rpafproxyipnum++;
			ows = ws;
		}

		MALLOC(rpafproxyips, char *, rpafproxyipnum);

		/* Store elements */
		ows = true;
		start = NULL;
		for (p = value; ; p++)
		{
			ws = (*p == ',' || *p == ' ' || *p == '\t' || !*p);
			if (ows && !ws)
				start = p;
			else if (!ows && ws)
				rpafproxyips[i++] = strndup(start, p - start);
			ows = ws;
			if (!*p)
				break;
		}
	}
	else if (!strcasecmp(name, "RpafHeader"))
	{
		if (rpafheader)
			FREE(rpafheader);
		STRDUP(rpafheader, value);
	}
	else
		return false;

	return true;
}

struct module rpaf_module =
{
	.name = "reverse proxy add forward",
	.init = NULL,
	.http_request = rpaf,
	.config_general = rpaf_config,
};

