/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */
#include	<sys/stat.h>

#include	"extra.h"
#include	"xscrypt.h"
#include	"mystring.h"

int
main(int argc, char **argv)
{
	char		*pwd, username[32], passbak[32], total[66],
			line[BUFSIZ], newfile[XS_PATH_MAX];
	const	char	*password;
	int		found, passwdlock;
	FILE		*authinp, *authout;

	umask(S_IRWXG | S_IRWXO);
	printf("The information will be stored in %s\n\n", AUTHFILE);
	printf("Please enter a username: "); fflush(stdout);
	if (!fgets(username, 16, stdin))
		errx(1, "Username input failed");
	while (username[0] && (username[strlen(username) - 1] < ' '))
		username[strlen(username) - 1] = 0;
	if (strchr(username, ':'))
		errx(1, "Username may not contain a colon");
	if (!(password = (const char *)getpass("Please enter a password: ")))
		errx(1, "Password input failed");
	strncpy(passbak, password, 32);
	passbak[31] = '\0';
	if (!(password = (const char *)getpass("Please reenter password: ")))
		errx(1, "Password input failed");
	if (strcmp(password, passbak))
		errx(1, "Password did not match previous entry!");
	printf("Lock this password (y/n): ");
	if (!fgets(line, 16, stdin))
		errx(1, "Lock input failed");
	passwdlock = ((line[0] == 'y') || (line[0] == 'Y'));
	pwd = xs_encrypt(password);
	sprintf(total, "%c%s:%s", passwdlock ? 'L' : 'U', username, pwd);
	authinp = fopen(AUTHFILE, "r");
	sprintf(newfile, "%s.new", AUTHFILE);
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
	(void)argc;
	(void)argv;
	exit(0);
}
