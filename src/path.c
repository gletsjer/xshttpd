/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	<string.h>
#include	<stdlib.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"path.h"

const	char	*
calcpath(const char *filename)
{
	static	char	buffer[XS_PATH_MAX];
	const	char	*rootdir;

#ifdef		BUILD_HTTPD
	rootdir = config.systemroot;
#else		/* BUILD_HTTPD */
	rootdir = getenv("HTTPD_ROOT") ? getenv("HTTPD_ROOT") : HTTPD_ROOT;
#endif		/* BUILD_HTTPD */

	if (*filename == '/')
		strlcpy(buffer, filename, XS_PATH_MAX);
	else if (rootdir)
		snprintf(buffer, XS_PATH_MAX, "%s/%s", rootdir, filename);
	else
		snprintf(buffer, XS_PATH_MAX, HTTPD_ROOT "/%s", filename);
	return (buffer);
}
