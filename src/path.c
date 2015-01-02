/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<string.h>
#include	<stdlib.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"path.h"

const	char	*
calcpath(const char * const prefix, const char * const filename)
{
	static	char	buffer[XS_PATH_MAX];

	if (*filename == '/')
		strlcpy(buffer, filename, XS_PATH_MAX);
	else if (prefix && prefix[strlen(prefix)-1] == '/')
		snprintf(buffer, XS_PATH_MAX, "%s%s", prefix, filename);
	else if (prefix)
		snprintf(buffer, XS_PATH_MAX, "%s/%s", prefix, filename);
	else
		snprintf(buffer, XS_PATH_MAX, "/%s", filename);

	return (buffer);
}
