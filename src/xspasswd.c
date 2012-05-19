/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<ctype.h>
#include	<stdbool.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<sys/stat.h>

#include	<openssl/des.h>

#include	"httpd.h"
#include	"decode.h"
#include	"hash.h"
#include	"extra.h"
#include	"malloc.h"
#include	"xscrypt.h"

static void	usage(void) NORETURN;

static void
usage(void)
{
	errx(1, "[-options] [username]\n\n"
		"-b | -d\t\tBasic or Digest HTTP authentication\n"
		"-l | -u\t\tLock or unlock (allow) password modification\n"
		"-r\t\tRemove account from password file\n"
		"-f <file>\tUse filename in stead of %s\n", 
		AUTH_FILE);
}

int
main(int argc, char **argv)
{
	char		*pwd, *username, *passone, *filename,
			*total, line[BUFSIZ];
	const	char	*password;
	int		option;
	bool		passwdlock, digest, delete;

	umask(S_IRWXG | S_IRWXO);
	filename = total = NULL;
	passwdlock = digest = delete = false;
	while ((option = getopt(argc, argv, "bdf:hlru")) != EOF)
	{
		switch (option)
		{
		case 'b':
			digest = false;
			break;
		case 'd':
			digest = true;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'l':
			passwdlock = true;
			break;
		case 'r':
			delete = true;
			break;
		case 'u':
			passwdlock = false;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage();
	if (!filename)
		STRDUP(filename, AUTH_FILE);
	printf("The information will be stored in %s\n\n", filename);

	if (argc)
		STRDUP(username, argv[0]);
	else
	{
		char	*u;

		printf("Please enter a username: "); fflush(stdout);
		if (!fgets(line, sizeof(line), stdin))
			errx(1, "Username input failed");
		for (u = line; *u; u++)
			if (isspace(*u))
				*u = '\0';
		STRDUP(username, line);
	}
	if (strchr(username, ':'))
		errx(1, "Username may not contain a colon");
	if (!delete)
	{
		STRDUP(passone, getpass("Please enter a password: "));
		if (!passone)
			errx(1, "Password input failed");
		if (!(password = (const char *)getpass("Please reenter password: ")))
			errx(1, "Password input failed");
		if (strcmp(password, passone))
			errx(1, "Password did not match previous entry!");
		pwd = DES_crypt(password, mksalt());

		if (digest)
		{
			char	*ha1 = generate_ha1(username, password);

			if (ha1)
				ASPRINTF(&total, "%c%s:%s:%s\n",
					(passwdlock ? 'L' : 'U'),
					username, pwd, ha1);
			else
				errx(1, "Digest authentication error");
		}
		else
			ASPRINTF(&total, "%c%s:%s\n",
				(passwdlock ? 'L' : 'U'), username, pwd);
		FREE(passone);
	}

	/* DECL */
	FILE		*authinp, *authout;
	char		*newfile;
	bool		found = false;
	size_t		count = 0;

	authinp = fopen(filename, "r");
	if (delete && !authinp)
		err(1, "Cannot open authentication file");

	ASPRINTF(&newfile, "%s.new", filename);
	if (!(authout = fopen(newfile, "w")))
		err(1, "Cannot write new authentication file");

	while (authinp && fgets(line, sizeof(line), authinp))
	{
		count++;
		if (!strncmp(line + 1, username, strlen(username)) &&
			(line[strlen(username) + 1] == ':'))
		{
			found = true;
			if (!delete)
				fputs(total, authout);
			else
				count--;
		} else
			fputs(line, authout);
	}
	if (found && delete)
		printf("Access for `%s' has been removed.\n", username);
	else if (found)
		printf("Password for `%s' has been changed.\n", username);
	else if (delete)
		printf("User `%s' not found in passwordfile.\n", username);
	else /* not found: add */
	{
		count++;
		fputs(total, authout);
		printf("New user `%s' has been created.\n", username);
	}
	FREE(username);
	FREE(total);
	if (authinp)
		fclose(authinp);
	fclose(authout);
	if (rename(newfile, filename))
		err(1, "Cannot rename authentication file");
	FREE(newfile);
	if (!count)
	{
		printf("Authentication file is now completely empty: "
			"removing file...\n");
		unlink(filename);
	}
	return 0;
}
