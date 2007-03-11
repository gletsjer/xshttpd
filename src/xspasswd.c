/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: xspasswd.c,v 1.19 2007/03/11 10:06:31 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<ctype.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<sys/stat.h>
#ifdef		HAVE_MD5
#include	<md5.h>
#endif		/* HAVE_MD5 */

#include	"httpd.h"
#include	"extra.h"
#include	"authenticate.h"
#include	"xscrypt.h"

int
main(int argc, char **argv)
{
	char		*pwd, *username, *passone,
			*total, line[BUFSIZ], *newfile;
	const	char	*password;
	int		found, option, passwdlock = 0, digest;
	FILE		*authinp, *authout;

#ifdef		HAVE_MD5
	digest = 1;
#else		/* HAVE_MD5 */
	digest = 0;
#endif		/* HAVE_MD5 */

	umask(S_IRWXG | S_IRWXO);
	while ((option = getopt(argc, argv, "bdhlu")) != EOF)
	{
		switch (option)
		{
		case 'b':
			digest = 0;
			break;
		case 'd':
			digest = 1;
			break;
		case 'l':
			passwdlock = 1;
			break;
		case 'u':
			passwdlock = 0;
			break;
		default:
			errx(1, "Usage: xspasswd [-l] [user]");
		}
	}
	argc -= optind;
	argv += optind;

	printf("The information will be stored in %s\n\n", AUTHFILE);
	if (argc > 1)
		errx(1, "Usage: xspasswd [-l] [user]");
	else if (argc)
		username = strdup(argv[0]);
	else
	{
		char	*u;

		printf("Please enter a username: "); fflush(stdout);
		if (!fgets(line, sizeof(line), stdin))
			errx(1, "Username input failed");
		for (u = line; *u; u++)
			if (isspace(*u))
				*u = '\0';
		username = strdup(line);
	}
	if (strchr(username, ':'))
		errx(1, "Username may not contain a colon");
	if (!(passone = strdup(getpass("Please enter a password: "))))
		errx(1, "Password input failed");
	if (!(password = (const char *)getpass("Please reenter password: ")))
		errx(1, "Password input failed");
	if (strcmp(password, passone))
		errx(1, "Password did not match previous entry!");
	pwd = xs_encrypt(password);

	if (digest)
	{
#ifdef		HAVE_MD5
		char	ha1[MD5_DIGEST_STRING_LENGTH];

		generate_ha1(username, password, ha1);
		asprintf(&total, "%c%s:%s:%s\n",
			(passwdlock ? 'L' : 'U'), username, pwd, ha1);
#else		/* HAVE_MD5 */
		errx(1, "Digest authentication is not supported");
#endif		/* HAVE_MD5 */
	}
	else
		asprintf(&total, "%c%s:%s\n",
			(passwdlock ? 'L' : 'U'), username, pwd);
	free(passone);

	authinp = fopen(AUTHFILE, "r");
	asprintf(&newfile, "%s.new", AUTHFILE);
	if (!(authout = fopen(newfile, "w")))
		err(1, "fopen(`%s', `w')", newfile);
	found = 0;
	while (authinp && fgets(line, sizeof(line), authinp))
	{
		if (!strncmp(line + 1, username, strlen(username)) &&
			(line[strlen(username) + 1] == ':'))
		{
			found = 1;
			fputs(total, authout);
		} else
			fputs(line, authout);
	}
	if (found)
		printf("Password for `%s' has been changed.\n", username);
	else
	{
		fputs(total, authout);
		printf("New user `%s' has been created.\n", username);
	}
	free(username);
	free(total);
	if (authinp)
		fclose(authinp);
	fclose(authout);
	if (rename(newfile, AUTHFILE))
		err(1, "Cannot rename(`%s', `%s')", newfile, AUTHFILE);
	free(newfile);
	return 0;
}
