/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: xspasswd.c,v 1.17 2007/02/20 18:13:32 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<sys/stat.h>

#include	"extra.h"
#include	"xscrypt.h"

int
main(int argc, char **argv)
{
	char		*pwd, username[XS_USER_MAX], passbak[XS_USER_MAX],
			total[XS_USER_MAX * 2 + 3],
			line[BUFSIZ], newfile[XS_PATH_MAX];
	const	char	*password;
	int		found, option, passwdlock = 0;
	FILE		*authinp, *authout;

	umask(S_IRWXG | S_IRWXO);
	while ((option = getopt(argc, argv, "hlu")) != EOF)
	{
		switch (option)
		{
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
		strlcpy(username, argv[0], XS_USER_MAX);
	else
	{
		printf("Please enter a username: "); fflush(stdout);
		if (!fgets(username, XS_USER_MAX, stdin))
			errx(1, "Username input failed");
		while (username[0] && (username[strlen(username) - 1] < ' '))
			username[strlen(username) - 1] = 0;
	}
	if (strchr(username, ':'))
		errx(1, "Username may not contain a colon");
	if (!(password = (const char *)getpass("Please enter a password: ")))
		errx(1, "Password input failed");
	strlcpy(passbak, password, XS_USER_MAX);
	if (!(password = (const char *)getpass("Please reenter password: ")))
		errx(1, "Password input failed");
	if (strcmp(password, passbak))
		errx(1, "Password did not match previous entry!");
	pwd = xs_encrypt(password);
	snprintf(total, sizeof(total), "%c%s:%s",
		(int)(passwdlock ? 'L' : 'U'), username, pwd);
	authinp = fopen(AUTHFILE, "r");
	snprintf(newfile, XS_PATH_MAX, "%s.new", AUTHFILE);
	if (!(authout = fopen(newfile, "w")))
		err(1, "fopen(`%s', `w')", newfile);
	found = 0;
	while (authinp && fgets(line, BUFSIZ, authinp))
	{
		if (!strncmp(line + 1, username, strlen(username)) &&
			(line[strlen(username) + 1] == ':'))
		{
			found = 1;
			fprintf(authout, "%s\n", total);
		} else
			fprintf(authout, "%s", line);
	}
	if (found)
		printf("Password for `%s' has been changed.\n", username);
	else
	{
		fprintf(authout, "%s\n", total);
		printf("New user `%s' has been created.\n", username);
	}
	if (authinp)
		fclose(authinp);
	fclose(authout);
	if (rename(newfile, AUTHFILE))
		err(1, "Cannot rename(`%s', `%s')", newfile, AUTHFILE);
	return 0;
}
