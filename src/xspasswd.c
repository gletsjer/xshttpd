/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

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
#ifdef		HAVE_CRYPT_H
#include	<crypt.h>
#endif		/* HAVE_CRYPT_H */

#include	"htconfig.h"
#include	"httpd.h"
#include	"decode.h"
#include	"extra.h"
#include	"authenticate.h"
#include	"xscrypt.h"

int
main(int argc, char **argv)
{
	char		*pwd, *username, *passone, *filename,
			*total, line[BUFSIZ], *newfile;
	const	char	*password;
	int		found, option, passwdlock = 0, digest = 0;
	FILE		*authinp, *authout;

	umask(S_IRWXG | S_IRWXO);
	filename = NULL;
	while ((option = getopt(argc, argv, "bdf:hlu")) != EOF)
	{
		switch (option)
		{
		case 'b':
			digest = 0;
			break;
		case 'd':
#ifndef		HAVE_MD5
			errx(1, "Digest authentication is not available");
#endif		/* HAVE_MD5 */
			digest = 1;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'l':
			passwdlock = 1;
			break;
		case 'u':
			passwdlock = 0;
			break;
		default:
			errx(1, "Usage: xspasswd [-b|-d] [-l|-u] "
				"[-f filename] [user]");
		}
	}
	argc -= optind;
	argv += optind;

	if (!filename)
		filename = strdup(AUTH_FILE);
	printf("The information will be stored in %s\n\n", filename);
	if (argc > 1)
		errx(1, "Usage: xspasswd [-b|-d] [-l|-u] [user]");
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
	pwd = crypt(password, mksalt());

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

	authinp = fopen(filename, "r");
	asprintf(&newfile, "%s.new", filename);
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
	if (rename(newfile, filename))
		err(1, "Cannot rename(`%s', `%s')", newfile, filename);
	free(newfile);
	return 0;
}
