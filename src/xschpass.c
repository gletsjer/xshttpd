/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<string.h>
#include	<ctype.h>

#include	<openssl/des.h>

#include	"extra.h"
#include	"decode.h"
#include	"hash.h"
#include	"xscrypt.h"
#include	"malloc.h"

static	void	xserror			(int, const char *, ...)	PRINTF_LIKE(2,3) NORETURN;
static	void	urldecode		(char *);
static	void	changepasswd		(const char *, int);
static	void	generateform		(void);
int	main			(int, char *[]);

static	void
xserror(int code, const char *format, ...)
{
	va_list		ap;
	char		*msg, *htmlmsg;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	/* error message should not contain any html */
	htmlmsg = escape(msg);

	printf("Status: %d Password change failed\n"
		"Content-type: text/html\n\n"
		"<HTML><HEAD><TITLE>%s</TITLE></HEAD>\n"
		"<BODY><H1>%s</H1>\n%s</BODY></HTML>\n",
		code, htmlmsg, htmlmsg, htmlmsg);
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
				*what = (d1-hexdigits) << 4 | (d2-hexdigits);
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
			*cryptnew, *cryptold;
	struct	stat	statbuf1, statbuf2;
	FILE		*input, *output;

	umask(S_IRWXG | S_IRWXO);
	filename[0] = '/';
	strlcpy(filename + 1, param, XS_PATH_MAX - 64);
	if (cl > (BUFSIZ - 64))
		xserror(400, "Too much input from your browser (%d bytes)", cl);
	if (read(0, buffer, cl) != cl)
		xserror(400, "Invalid content length");
	buffer[cl] = 0;
	urldecode(buffer);
	username[0] = old[0] = new1[0] = new2[0] = 0;
	search = buffer;
	while (*search)
	{
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
			xserror(404, "Unknown field '%s'", search);
		}
		search = strchr(search, '\0') + 1;
	}
	if (!username[0] || !old[0] || !new1[0] || !new2[0])
		xserror(403, "Not all fields were filled in correctly!");
	if (strcmp(new1, new2))
		xserror(403, "You did not type the new password correctly two times!");
	for (search = new1; *search; search++)
		if (*search < ' ')
			xserror(403, "Your password contains an invalid character!");
	STRDUP(cryptnew, DES_crypt(new1, mksalt()));

	if (stat(filename, &statbuf1))
		xserror(403, "Could not stat directory '%s': %s",
			filename, strerror(errno));
	if (!S_ISDIR(statbuf1.st_mode))
		xserror(403, "'%s' is not a directory", filename);
	strlcat(filename, "/", XS_PATH_MAX);
	strlcat(filename, AUTH_FILE, XS_PATH_MAX);
	if (lstat(filename, &statbuf2))
		xserror(403, "Could not lstat password file '%s': %s",
			filename, strerror(errno));
	if ((statbuf2.st_mode & S_IFMT) != S_IFREG)
		xserror(403, "Password file is not a regular file");
	if (statbuf1.st_uid != statbuf2.st_uid)
		xserror(403, "File and directory user ID's do not match");
	if (!statbuf1.st_uid)
		xserror(403, "Directory is owned by root");

	if (!(input = fopen(filename, "r")))
		xserror(403, "Could not fopen password file '%s': %s",
			filename, strerror(errno));

	strlcat(filename, ".new", XS_PATH_MAX);
	if (!lstat(filename, &statbuf2))
		xserror(403, "Somebody is already changing a password, please retry again in a few moments!");
	if (!(output = fopen(filename, "w")))
		xserror(403, "Could not fopen new password file '%s': %s",
			filename, strerror(errno));

	bool		found = false;
	snprintf(new2, BUFSIZ, "%s:", username);
	while (fgets(buffer, BUFSIZ, input))
	{
		if (!found && strlen(buffer) > 1 &&
			!strncmp(buffer+1, new2, strlen(new2)))
		{
			bool	digest;
			char	*opwent, *eol, *ha1;

			eol = strchr(buffer + strlen(new2) + 2, ':');
			digest = eol ? true : false;
			if (!eol && !(eol = strchr(buffer, '\n')))
				/* bad entry: skip, don't write */
				continue;
			*eol = '\0';
			opwent = buffer + 1 + strlen(new2);
			STRDUP(cryptold, DES_crypt(old, opwent));
			if (strcmp(cryptold, opwent))
			{
				fclose(input); fclose(output);
				remove(filename);
				xserror(403, "Password doesn't match");
			}
			free(cryptold);
			found = true;
			if (buffer[0] != 'U')
			{
				fclose(input); fclose(output);
				remove(filename);
				xserror(403, "Password is locked");
			}
			if ((search = strchr(buffer, ':')) &&
				strchr(search + 1, ':'))
			{
				fclose(input); fclose(output);
				remove(filename);
				xserror(403, "Cannot change authentication digests");
			}

			if (digest && (ha1 = generate_ha1(username, new1)))
				fprintf(output, "%c%s:%s:%s\n",
					buffer[0], username, cryptnew, ha1);
			else
				fprintf(output, "%c%s:%s\n",
					buffer[0], username, cryptnew);
		} else
			fputs(buffer, output);
	}
	fclose(input); fclose(output);
	if (!found)
	{
		remove(filename);
		xserror(403, "Old username/password combination not found");
	}
	strlcpy(buffer, filename, BUFSIZ);
	buffer[strlen(buffer) - 4] = 0;
	if (rename(filename, buffer))
		xserror(500, "Could not rename '%s' to '%s': %s",
			filename, buffer, strerror(errno));
	printf("Content-type: text/html\n\n");
	printf("<HTML><HEAD><TITLE>Password changed</TITLE></HEAD>\n");
	printf("<BODY><H1>Password changed</H1>\n");
	printf("The password has been changed!</BODY></HTML>\n");
}

static	void
generateform()
{
	char	*name = urlencode(getenv("SCRIPT_NAME"), false);
	char	*info = urlencode(getenv("PATH_INFO"), true);

	printf("Content-type: text/html\n\n");
	printf("<HTML><HEAD><TITLE>Change password</TITLE></HEAD>\n");
	printf("<BODY><H1>Change password</H1><PRE>\n");
	printf("<FORM METHOD=\"POST\" ACTION=\"%s%s\">\n", name, info);
	printf("User name:      <INPUT NAME=\"username\" TYPE=\"text\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("Old password:   <INPUT NAME=\"old\" TYPE=\"password\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("New password:   <INPUT NAME=\"new1\" TYPE=\"password\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("Enter it again: <INPUT NAME=\"new2\" TYPE=\"password\" MAXLENGTH=16 SIZE=16><P>\n");
	printf("<INPUT TYPE=\"submit\" VALUE=\"Change password\"> |\n");
	printf("<INPUT TYPE=\"reset\" VALUE=\"Clear form\">\n</FORM>");
	printf("</PRE></BODY></HTML>\n");
	free(name);
	free(info);
}

int
main(int argc, char **argv)
{
	const	char	*param, *cl;
	int		length;

	alarm(120);
	if (!(param = getenv("PATH_TRANSLATED")))
		xserror(404, "Incorrect usage - supply directory name");
	while (*param == '/')
		param++;
	cl = getenv("CONTENT_LENGTH");
	if (cl && ((length = strtoul(cl, NULL, 0)) > 0))
		changepasswd(param, length);
	else
		generateform();
	(void)argc;
	(void)argv;
	return 0;
}
