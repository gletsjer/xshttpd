/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* $Id: httpdc.c,v 1.17 2005/08/19 12:26:18 johans Exp $ */

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
#include	<ctype.h>

#include	"mygetopt.h"
#include	"mystring.h"
#include	"httpd.h"
#include	"path.h"
#include	"htconfig.h"

typedef	struct
{
	const	char	*command;
	void		(*func) (const char *);
	const	char	*help;
} command;

static	pid_t	httpdpid;
static	char	startparams[BUFSIZ];
char		rootdir[XS_PATH_MAX];

struct virtual			*current;
struct configuration	config;

static	void	cmd_help	(const char *);
static	void	cmd_status	(const char *);
static	void	cmd_kill	(const char *);
static	void	cmd_reload	(const char *);
static	void	cmd_restart	(const char *);
static	void	control		(const char *);

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

static	void
cmd_help(const char *args)
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

static	void
cmd_status(const char *args)
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

static	void
cmd_kill(const char *args)
{
	if (kill(httpdpid, SIGTERM))
		warn("kill");
	else
		printf("Main HTTPD killed, children will die too.\n");
	(void)args;
}

static	void
cmd_restart(const char *args)
{
	int		timeout;

	if (kill(httpdpid, SIGTERM))
		warn("kill");
	printf("Main HTTPD killed, children will die automatically.\n");
	printf("Waiting for children to die... ");
	timeout = 600;
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

static	void
cmd_reload(const char *args)
{
	if (kill(httpdpid, SIGHUP))
		warn("kill()");
	else
		printf("Databases reloaded...\n");
	(void)args;
}

static	void
control(const char *args)
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

static	void
getpidfilename(char **pidfilename)
{
	char		*p, buffer[BUFSIZ], config_path[XS_PATH_MAX];
	FILE		*conffile;

	snprintf(config_path, XS_PATH_MAX, "%s/httpd.conf", calcpath(rootdir));
	if (!(conffile = fopen(config_path, "r")))
		return;

	while (fgets(buffer, BUFSIZ, conffile))
	{
		if (strncasecmp(buffer, "PidFile", 7))
			continue;
		for (p = buffer + 7; *p && isspace((int)*p); p++)
			/* DO NOTHING */;
		*pidfilename = strdup(p);
		for (p = *pidfilename; *p; p++)
			if (isspace((int)*p))
				*p = '\0';
		break;
	}
	fclose(conffile);
}

static	void
loadpidfile(const char *pidfilename)
{
	char		buffer[BUFSIZ], pidname[XS_PATH_MAX];
	FILE		*pidfile;

	strlcpy(pidname,
		pidfilename == NULL ? calcpath(PID_PATH) : pidfilename,
		XS_PATH_MAX);
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

int
main(int argc, char **argv)
{
	char		buffer[BUFSIZ];
	char		*pidfilename = NULL;
	int		option;

	strcpy(rootdir, HTTPD_ROOT);
	while ((option = getopt(argc, argv, "d:p:")) != EOF)
	{
		switch(option)
		{
		case 'd':
			strlcpy(rootdir, optarg, XS_PATH_MAX);
			break;
		case 'p':
			pidfilename = optarg;
			break;
		default:
			err(1, "Usage: %s [-d rootdir] [-p pidfile]", argv[0]);
		}
	}
	if (!pidfilename)
		getpidfilename(&pidfilename);

	if (argc != optind)
	{
		loadpidfile(pidfilename);
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
		loadpidfile(pidfilename);
		control(buffer);
	}
	fprintf(stderr, "End of input received\n");
	exit(0);
}
