/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: xschpass.c,v 1.20 2007/03/13 23:31:35 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<string.h>
#include	<ctype.h>

#include	"extra.h"
#include	"xscrypt.h"

static	void	error			(const char *, ...);
static	void	urldecode		(char *);
static	void	changepasswd		(const char *, int);
static	void	generateform		(void);
int	main			(int, char *[]);

static	void
error(const char *format, ...)
{
	va_list		ap;

	va_start(ap, format);

	alarm(180);

	printf("Content-type: text/html\n\n");
	printf("<HTML><HEAD><TITLE>");
	vprintf(format, ap);
	printf("</TITLE></HEAD>\n<BODY>\n<H1>");
	vprintf(format, ap);
	printf("</H1>\n");
	vprintf(format, ap);
	printf("</BODY></HTML>\n");
	va_end(ap);
	exit(1);
}

static	void
urldecode(char *what)
{
	static	const	char	*hexdigits = "0123456789ABCDEF";
	const	char		*d1, *d2;

	while (*what)
	{
		if (*what == '+')
			*what = ' ';
		if (*what == '&')
			*what = 0;
		if (*what == '%')
		{
			if ((d1 = strchr(hexdigits,
					islower(what[1]) ? toupper(what[1]) : what[1])) &&
			    (d2 = strchr(hexdigits,
					islower(what[2]) ? toupper(what[2]) : what[2])))
			{
				*what = (d1-hexdigits)*16 + (d2-hexdigits);
				memmove(what + 1, what + 3, strlen(what) - 2);
			}
		}
		what++;
	}
	*(++what) = 0;
}

static	void
changepasswd(const char *param, int  cl)
{
	char		filename[XS_PATH_MAX], username[BUFSIZ], old[BUFSIZ],
			new1[BUFSIZ], new2[BUFSIZ], buffer[BUFSIZ], *search,
			*search2, *cryptnew, *cryptold;
	struct	stat	statbuf1, statbuf2;
	FILE		*input, *output;
	int		found;

	alarm(120); filename[0] = '/';
	strlcpy(filename + 1, param, XS_PATH_MAX - 64);
	if (cl > (BUFSIZ - 64))
		error("400 Too much input from your browser (%d bytes)", cl);
	if (read(0, buffer, cl) != cl)
		error("400 Invalid content length");
	buffer[cl] = 0;
	urldecode(buffer);
	username[0] = old[0] = new1[0] = new2[0] = 0;
	search = buffer;
	while (*search)
	{
		for (search2 = search; *search2; search2++) ;
		if (!strncasecmp("username=", search, 9))
			strlcpy(username, search + 9, BUFSIZ);
		else if (!strncasecmp("old=", search, 4))
			strlcpy(old, search + 4, BUFSIZ);
		else if (!strncasecmp("new1=", search, 5))
			strlcpy(new1, search + 5, BUFSIZ);
		else if (!strncasecmp("new2=", search, 5))
			strlcpy(new2, search + 5, BUFSIZ);
		else
		{
			strtok(search, "=");
			error("404 Unknown field '%s'", search);
		}
		search = search2 + 1;
	}
	if (!username[0] || !old[0] || !new1[0] || !new2[0])
		error("403 Not all fields were filled in correctly!");
	if (strcmp(new1, new2))
		error("403 You did not type the new password correctly two times!");
	for (search = new1; *search; search++)
		if (*search < ' ')
			error("403 Your password contains an invallid character!");
	cryptnew = xs_encrypt(new1);
	cryptold = xs_encrypt(old);

	if (lstat(filename, &statbuf1))
		error("403 Could not lstat directory '%s': %s",
			filename, strerror(errno));
	if (S_ISDIR(statbuf1.st_mode))
		error("403 '%s' is not a directory", filename);
	strlcat(filename, "/", XS_PATH_MAX);
	strlcat(filename, AUTHFILE, XS_PATH_MAX);
	if (lstat(filename, &statbuf2))
		error("403 Could not lstat password file '%s': %s",
			filename, strerror(errno));
	if ((statbuf2.st_mode & S_IFMT) != S_IFREG)
		error("403 Password file is not a regular file");
	if (statbuf1.st_uid != statbuf2.st_uid)
		error("403 File and directory user ID's do not match");
	if (!statbuf1.st_uid)
		error("403 Directory is owned by root");

	if (!(input = fopen(filename, "r")))
		error("403 Could not fopen password file '%s': %s",
			filename, strerror(errno));

	strlcat(filename, ".new", XS_PATH_MAX);
	if (!lstat(filename, &statbuf2))
		error("403 Somebody is already changing a password, please retry again in a few moments!");
	if (!(output = fopen(filename, "w")))
		error("403 Could not fopen new password file '%s': %s",
			filename, strerror(errno));
	if (chown(filename, statbuf1.st_uid, statbuf1.st_gid))
		error("403 Could not chown new password file '%s': %s",
			filename, strerror(errno));

	found = 0;
	snprintf(new2, BUFSIZ, "%s:%s\n", username, cryptold);
	while (fgets(buffer, BUFSIZ, input))
	{
		if (!found && !strcmp(buffer+1, new2))
		{
			found = 1;
			if (buffer[0] != 'U')
			{
				fclose(input); fclose(output);
				remove(filename);
				error("403 Password is locked");
			}
			if ((search = strchr(buffer + 2, ':')) &&
				strchr(search + 1, ':'))
			{
				fclose(input); fclose(output);
				remove(filename);
				error("403 Cannot change authentication digests");
			}
			fprintf(output, "%c%s:%s\n",
				buffer[0], username, cryptnew);
		} else
			fprintf(output, "%s", buffer);
	}
	fclose(input); fclose(output);
	if (!found)
	{
		remove(filename);
		error("403 Old username/password combination not found");
	}
	strlcpy(buffer, filename, BUFSIZ);
	buffer[strlen(buffer) - 4] = 0;
	if (rename(filename, buffer))
		error("500 Could not rename '%s' to '%s': %s",
			filename, buffer, strerror(errno));
	printf("Content-type: text/html\n\n");
	printf("<HTML><HEAD><TITLE>Password changed</TITLE></HEAD>\n");
	printf("<BODY><H1>Password changed</H1>\n");
	printf("The password has been changed!</BODY></HTML>\n");
}

static	void
generateform()
{
	alarm(180);
	printf("Content-type: text/html\n\n");
	printf("<HTML><HEAD><TITLE>Change password</TITLE></HEAD>\n");
	printf("<BODY><H1>Change password</H1><PRE>\n");
	printf("<FORM METHOD=\"POST\" ACTION=\"%s%s\">\n",
		getenv("SCRIPT_NAME"), getenv("PATH_INFO"));
	printf("User name:      <INPUT NAME=\"username\" TYPE=\"text\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("Old password:   <INPUT NAME=\"old\" TYPE=\"password\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("New password:   <INPUT NAME=\"new1\" TYPE=\"password\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("Enter it again: <INPUT NAME=\"new2\" TYPE=\"password\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("<INPUT TYPE=\"submit\" VALUE=\"Change password\"> |\n");
	printf("<INPUT TYPE=\"reset\" VALUE=\"Clear form\">\n</FORM>");
	printf("</PRE></BODY></HTML>\n");
}

int
main(int argc, char **argv)
{
	const	char	*param, *cl;
	int		length;

	if (geteuid())
		error("501 Incorrect user ID for operation");
	if (!(param = getenv("PATH_TRANSLATED")))
		error("404 Incorrect usage - supply directory name");
	while (*param == '/')
		param++;
	cl = getenv("CONTENT_LENGTH");
	if (cl && ((length = atoi(cl)) > 0))
		changepasswd(param, length);
	else
		generateform();
	(void)argc;
	(void)argv;
	return 0;
}
