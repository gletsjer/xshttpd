/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: httpdc.c,v 1.5 2001/05/22 12:19:29 johans Exp $ */

#include	"config.h"

#include	<sys/types.h>
#include	<signal.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */
#include	<errno.h>

#include	"mygetopt.h"
#include	"mystring.h"
#include	"httpd.h"
#include	"path.h"

typedef	struct
{
	const	char	*command;
	VOID		(*func)
#ifndef		NONEWSTYLE
				(const char *);
#else		/* Not NONEWSTYLE */
				();
#endif		/* NONEWSTYLE */
	const	char	*help;
} command;

static	pid_t	httpdpid;
static	char	startparams[BUFSIZ];
char		rootdir[XS_PATH_MAX];

#ifndef		NOFORWARDS
static	VOID	cmd_help	PROTO((const char *));
static	VOID	cmd_status	PROTO((const char *));
static	VOID	cmd_kill	PROTO((const char *));
static	VOID	cmd_reload	PROTO((const char *));
static	VOID	cmd_restart	PROTO((const char *));
static	VOID	control		PROTO((const char *));
#endif		/* NOFORWARDS */

static	command	commands[]=
{
	{ "?",		cmd_help,	"Display this help text",	},
	{ "help",	cmd_help,	"Display this help text"	},
	{ "status",	cmd_status,	"Display httpd status"		},
	{ "kill",	cmd_kill,	"Terminate the httpd"		},
	{ "reload",	cmd_reload,	"Reload all httpd databases"	},
	{ "restart",	cmd_restart,	"Restart httpd with previous command lines arguments"	},
	{ "quit",	NULL,		"Quit the control program"	},
	{ "exit",	NULL,		"Quit the control program"	},
	{ NULL,		NULL,		NULL				}
};

static	VOID
cmd_help DECL1C(char *, args)
{
	command		*search;

	search = commands;
	while (search->command)
	{
		printf("%s\t\t%s\n", search->command, search->help);
		search++;
	}
	(void)args;
}

static	VOID
cmd_status DECL1C(char *, args)
{
	if (kill(httpdpid, 0))
	{
		if (errno == ESRCH)
			printf("Main HTTPD does not seem to be running\n");
		else
			warn("kill()");
	} else
		printf("Main HTTPD seems to be running\n");
	if (killpg(httpdpid, 0))
	{
		if (errno == ESRCH)
			printf("HTTPD process group does not seem to be running\n");
		else
			warn("killpg()");
	} else
		printf("HTTPD process group seems to be running\n");
	printf("Main HTTPD PID: %ld\n", (long)httpdpid);
	printf("Last used command line: %s\n", startparams);
	(void)args;
}

static	VOID
cmd_kill DECL1C(char *, args)
{
	if (kill(httpdpid, SIGTERM))
		warn("kill");
	else
		printf("Main HTTPD killed, children will die too.\n");
	(void)args;
}

static	VOID
cmd_restart DECL1C(char *, args)
{
	int		timeout;

	if (kill(httpdpid, SIGTERM))
		warn("kill");
	printf("Main HTTPD killed, children will die automatically.\n");
	printf("Waiting for children to die... ");
	timeout = 120;
	while (!killpg(httpdpid, 0) && (timeout > 0))
	{
		printf("%c\b", (char)*("/-\\|" + (timeout & 3)));
		fflush(stdout); sleep(1); timeout--;
	}
	if (!killpg(httpdpid, 0))
	{
		fprintf(stderr, "The children would not die within 120 seconds!\n");
		return;
	}
	printf("Children are dead!\n");
	printf("Restarting httpd... "); fflush(stdout);
	system(startparams);
	printf("Done!\n");
	printf("Executed: %s\n", startparams);
	(void)args;
}

static	VOID
cmd_reload DECL1C(char *, args)
{
	if (kill(httpdpid, SIGHUP))
		warn("kill()");
	else
		printf("Databases reloaded...\n");
	(void)args;
}

static	VOID
control DECL1C(char *, args)
{
	char		buffer[BUFSIZ], *space;
	command		*search;

	strcpy(buffer, args);
	space = buffer;
	while (*space && (*space != 9) && (*space != ' '))
		space++;
	if (*space)
	{
		*(space++) = 0;
		while ((*space == 9) || (*space == ' '))
			space++;
	}
	search = commands;
	while (search->command)
	{
		if (!strcasecmp(search->command, buffer))
		{
			if (search->func)
				search->func(space);
			else
				exit(0);
			return;
		}
		search++;
	}
	fprintf(stderr, "Command `%s' not found\n", buffer);
}

static	VOID
loadpidfile DECL0
{
	char		buffer[BUFSIZ], pidname[XS_PATH_MAX];
	FILE		*pidfile;

	strcpy(pidname, calcpath(PID_PATH));
	if ((pidfile = fopen(pidname, "r")))
	{
		if (!fgets(buffer, BUFSIZ, pidfile))
			errx(1, "PID line in `%s' is corrupt\n", pidname);
		else
		{
			httpdpid = (pid_t)atol(buffer);
			if (!fgets(startparams, BUFSIZ, pidfile))
				errx(1, "Arguments line in `%s' is corrupt\n",
					pidname);
		}
	} else
		err(1, "fopen(%s)", pidname);
}

extern	int
main DECL2(int, argc, char **, argv)
{
	char		buffer[BUFSIZ];
	int		option;

	strcpy(rootdir, HTTPD_ROOT);
	while ((option = getopt(argc, argv, "d:")) != EOF)
	{
		switch(option)
		{
		case 'd':
			strcpy(rootdir, optarg);
			break;
		default:
			err(1, "Usage: %s [-d rootdir]", argv[0]);
		}
	}
	if (argc != optind)
	{
		loadpidfile();
		control(argv[optind]);
		exit(0);
	}

	while (1)
	{
		printf("httpdc> "); fflush(stdout);
		if (!fgets(buffer, BUFSIZ, stdin))
			break;
		while (buffer[0] && (buffer[strlen(buffer) - 1] <= ' '))
			buffer[strlen(buffer) - 1] = 0;
		if (!buffer[0])
			continue;
		loadpidfile();
		control(buffer);
	}
	fprintf(stderr, "End of input received\n");
	exit(0);
}
