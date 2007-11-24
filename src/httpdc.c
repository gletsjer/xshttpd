/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2007 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<signal.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<errno.h>
#include	<string.h>
#include	<ctype.h>

#include	"httpd.h"
#include	"path.h"
#include	"htconfig.h"

typedef	struct
{
	const	char	*command;
	void		(*func) (const char *);
	const	char	*help;
} command;

static	pid_t	httpdpid;	/* a value of 0 denotes no running httpd */
static	char	startparams[BUFSIZ];
char		rootdir[XS_PATH_MAX];

struct virtual			*current;
struct configuration	config;

static	void	cmd_help	(const char *);
static	void	cmd_status	(const char *);
static	void	cmd_kill	(const char *);
static	void	cmd_stop	(const char *);
static	void	cmd_start	(const char *);
static	void	cmd_reload	(const char *);
static	void	cmd_restart	(const char *);
static	void	cmd_version	(const char *);
static	void	control		(const char *);

static	command	commands[]=
{
	{ "?",		cmd_help,	"Display this help text"	},
	{ "help",	cmd_help,	"Display this help text"	},
	{ "status",	cmd_status,	"Display httpd status"		},
	{ "start",	cmd_restart,	"Start httpd"			},
	{ "restart",	cmd_restart,	"Restart httpd"			},
	{ "reload",	cmd_reload,	"Reload all httpd databases"	},
	{ "stop",	cmd_stop,	"Terminate the httpd"		},
	{ "kill",	cmd_kill,	"Forcefully terminate the httpd"},
	{ "version",	cmd_version,	"Show httpdc version string"	},
	{ "quit",	NULL,		"Quit the control program"	},
	{ "exit",	NULL,		"Quit the control program"	},
	{ NULL,		NULL,		NULL				},
};

static	void
cmd_help(const char *args)
{
	command		*search;

	for (search = commands; search->command; search++)
		printf("%s\t\t%s\n", search->command, search->help);
	(void)args;
}

static	void
cmd_status(const char *args)
{
	if (!httpdpid)
		return;

	if (kill(httpdpid, 0))
	{
		if (errno == ESRCH)
			warnx("Main HTTPD does not seem to be running");
		else
			warn("kill()");
	}
	else
		printf("Main HTTPD seems to be running\n");

	if (killpg(httpdpid, 0))
	{
		if (errno == ESRCH)
			warnx("HTTPD process group does not seem to be running\n");
		else
			warn("killpg()");
	}
	else
		printf("HTTPD process group seems to be running\n");

	printf("Main HTTPD PID: %ld\n", (long)httpdpid);
	printf("Last used command line: %s\n", startparams);
	(void)args;
}

static	void
cmd_stop(const char *args)
{
	if (!httpdpid)
		return;

	if (kill(httpdpid, SIGTERM))
		warn("kill()");
	else
		printf("Main HTTPD terminated, children will die too.\n");
	(void)args;
}

static	void
cmd_kill(const char *args)
{
	int	timeout;

	if (!httpdpid)
		return;

	timeout = 600;
	printf("Killing HTTPD processes... ");
	while (!killpg(httpdpid, SIGKILL) && (timeout > 0))
	{
		printf("%c\b", "/-\\|"[timeout & 3]);
		fflush(stdout);
		sleep(1);
		timeout--;
	}
	if (!killpg(httpdpid, 0))
		warnx("The children would not die within %d seconds!", timeout);
	else
		printf("All children have been killed.\n");
	(void)args;
}

static	void
cmd_restart(const char *args)
{
	int		timeout = 600;

	if (!httpdpid ||
		(kill(httpdpid, 0) && errno == ESRCH))
	{
		/* server not running: goto start */
		cmd_start(args);
		return;
	}

	if (kill(httpdpid, SIGTERM))
		warn("kill()");
	printf("Main HTTPD killed, children will die automatically.\n");
	printf("Waiting for children to die... ");

	while (!killpg(httpdpid, 0) && (timeout > 0))
	{
		printf("%c\b", (char)*("/-\\|" + (timeout & 3)));
		fflush(stdout);
		sleep(1);
		timeout--;
	}

	if (!killpg(httpdpid, 0))
	{
		warnx("The children would not die within %d seconds!\n",
			timeout);
		return;
	}
	printf("Children are dead!\n");
	cmd_start(args);
}

static	void
cmd_start(const char *args)
{
	if (!httpdpid)
		printf("Starting with default options... ");
	else
		printf("Restarting httpd... ");

	fflush(stdout);
	system(startparams);
	printf("Done!\n");
	printf("Executed: %s\n", startparams);
	(void)args;
}

static	void
cmd_reload(const char *args)
{
	if (!httpdpid)
		return;

	if (kill(httpdpid, SIGHUP))
		warn("kill()");
	else
		printf("Databases reloaded...\n"
			"Run 'httpdc restart' to ensure that "
			"all configuration changes take effect.\n");

	(void)args;
}

static	void
cmd_version(const char *args)
{
	printf("%s\n", SERVER_IDENT);
	(void)args;
}

static	void
control(const char *args)
{
	char		buffer[BUFSIZ], *space;
	command		*search;

	strlcpy(buffer, args, BUFSIZ);
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
	warnx("Command `%s' not found\n", buffer);
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
	char	buffer[BUFSIZ], pidname[XS_PATH_MAX];
	FILE	*pidfile;

	strlcpy(pidname,
		pidfilename == NULL ? calcpath(PID_PATH) : pidfilename,
		XS_PATH_MAX);
	if ((pidfile = fopen(pidname, "r")))
	{
		if (!fgets(buffer, BUFSIZ, pidfile))
			errx(1, "PID line in `%s' is corrupt\n", pidname);
		else
		{
			httpdpid = (pid_t) atol(buffer);
			if (!fgets(startparams, BUFSIZ, pidfile))
				errx(1, "Arguments line in `%s' is corrupt\n",
				     pidname);
		}
	}
	else
	{
		warn("fopen(`%s')", pidname);
		httpdpid = 0;
		strlcpy(startparams, BINDIR "/httpd", BUFSIZ);
	}
}

int
main(int argc, char **argv)
{
	char		buffer[BUFSIZ];
	char		*pidfilename = NULL;
	int		option;

	strlcpy(rootdir, HTTPD_ROOT, BUFSIZ);
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
		return 0;
	}

	for (;;)
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
	return 0;
}
