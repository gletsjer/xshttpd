/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#ifdef		HAVE_SYS_TIME_H
#include	<sys/time.h>
#endif		/* HAVE_SYS_TIME_H */
#ifdef		HAVE_SYS_RESOURCE_H
#include	<sys/resource.h>
#endif		/* HAVE_SYS_RESOURCE_H */
#include	<fcntl.h>
#include	<sys/signal.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<errno.h>
#ifdef		HAVE_TIME_H
#ifdef		SYS_TIME_WITH_TIME
#include	<time.h>
#endif		/* SYS_TIME_WITH_TIME */
#endif		/* HAVE_TIME_H */
#include	<stdlib.h>
#include	<signal.h>
#include	<pwd.h>
#include	<grp.h>
#include	<unistd.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#else		/* Not HAVE_ERR_H */
#include	"err.h"
#endif		/* HAVE_ERR_H */
#include	<ctype.h>
#ifdef		HAVE_MEMORY_H
#include	<memory.h>
#endif		/* HAVE_MEMORY_H */

#include	"httpd.h"
#include	"local.h"
#include	"procname.h"
#include	"ssi.h"
#include	"extra.h"
#include	"path.h"
#include	"convert.h"
#include	"setenv.h"
#include	"string.h"

#ifndef		NOFORWARDS
static	const	char	*skipspaces	PROTO((const char *));
static	VOID	time_is_up		PROTO((int));
#endif		/* NOFORWARDS */

pid_t			child;


static	const	char	*
skipspaces DECL1C(char *, string)
{
	while ((*string == ' ') || (*string == '\t'))
		string++;
	return(string);
}

static	VOID
time_is_up DECL1(int, sig)
{
	if (child != (pid_t)-1)
	{
		killpg(child, SIGTERM);
		mysleep(1);
		killpg(child, SIGKILL);
	}
	alarm_handler(sig);
}

extern	VOID
do_script DECL2C_(char *, path, int, headers)
{
	struct	stat		statbuf;
	uid_t			savedeuid, currentuid;
	gid_t			savedegid, currentgid;
	long			size, received, written, writetodo,
				totalwritten;
	char			errmsg[MYBUFSIZ], fullpath[XS_PATH_MAX],
				status[MYBUFSIZ], contenttype[MYBUFSIZ], cachecontrol[MYBUFSIZ],
				location[MYBUFSIZ], base[XS_PATH_MAX], *temp,
				name[XS_PATH_MAX], *nextslash,
				tempbuf[XS_PATH_MAX + 32];
	const	char		*file, *argv1, *header;
	int			p[2], nph, count, nouid, was_slash;
#ifdef		SUPPORT_PHP3
	int		php3 = strlen(path) > 4 && (!strcmp(path+strlen(path)-5, ".php3") ||
				strstr(path, ".php3?"));
#endif		/* SUPPORT_PHP3 */
	unsigned	int	left;
	struct	rlimit		limits;
	const	struct	passwd	*userinfo;
	FILE			*auth;
	struct	sigaction	action;

	child = (pid_t)-1;
#ifdef		HAVE_SIGEMPTYSET
	sigemptyset(&action.sa_mask);
#else		/* Not HAVE_SIGEMPYSET */
	action.sa_mask = 0;
#endif		/* HAVE_SIGEMPTYSET */
	action.sa_handler = time_is_up;
	action.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);

	alarm(0); /* left = alarm(360); */ fflush(stdout);
	unsetenv("PATH_INFO"); unsetenv("PATH_TRANSLATED");
	unsetenv("QUERY_STRING"); unsetenv("SCRIPT_NAME");
	savedeuid = savedegid = -1;
	if (!origeuid)
	{
		savedeuid = geteuid(); seteuid(origeuid);
		savedegid = getegid(); setegid(origegid);
	}
	p[0] = p[1] = -1;

	userinfo = NULL; was_slash = 0;
	if ((path[0] == '/') && ((path[1] == '?') || !path[1]))
		was_slash = 1;

	if (path[0] != '/')
	{
		if (headers)
			error("403 Invalid pathname");
		else
			printf("[Invalid pathname]\n");
		goto END;
	}
	currentgid = -1;
	if (path[1] == '~')
	{
		strncpy(name, path + 2, 15);
		name[15] = 0;
		if ((temp = strchr(name, '/')))
			*temp = 0;
		if (!(userinfo = getpwnam(name)))
		{
			if (headers)
				error("404 User is unknown");
			else
				printf("[User `%s' is unknown]\n", name);
			goto END;
		}
		if (transform_user_dir(base, userinfo, headers))
		{
			if (!headers)
				printf("[User directory error]\n");
			goto END;
		}
		size = strlen(base);
#ifdef		SUPPORT_PHP3
		if (!php3)
#endif		/* SUPPORT_PHP3 */
		{
			strcpy(base + size, HTTPD_SCRIPT_ROOT);
			strcat(base + size, "/");
		}
		if (!origeuid)
		{
			setegid(currentgid = userinfo->pw_gid);
			setgroups(1, (gid_t *)&userinfo->pw_gid);
			seteuid(userinfo->pw_uid);
		}
		if (!(currentuid = geteuid()))
		{
			if (headers)
				error("500 Effective UID is not valid");
			else
				printf("[UID error]\n");
			goto END;
		}
		file = path + strlen(name) + 3;
	} else
	{
		if (php3)
		{
			if (headers)
				error("500 PHP3 not yet supported");
			else
				printf("[PHP3 not yet supported]\n");
			goto END;
		}
		if (!was_slash)
		{
			file = path + 1;
			strcpy(base, calcpath(HTTPD_SCRIPT_ROOT_P));
			strcat(base, "/");
		} else
		{
			sprintf(tempbuf, "cgi/nph-slash%s", path + 1);
			file = tempbuf;
			strcpy(base, calcpath(HTTPD_SCRIPT_ROOT_P));
			strcat(base, "/");
		}

		if (!origeuid)
		{
			setegid(currentgid = group_id);
			setgroups(1, &group_id);
			seteuid(user_id);
		}
		if (!(currentuid = geteuid()))
		{
			if (headers)
				error("500 Effective UID is not valid");
			else
				printf("[UID error]\n");
			goto END;
		}
	}

	size = strlen(HTTPD_SCRIPT_ROOT);
#ifdef		SUPPORT_PHP3
	if (php3)
		size = -1;
	if (!php3)
#endif		/* SUPPORT_PHP3 */
	if (strncmp(file, HTTPD_SCRIPT_ROOT, size) || (file[size] != '/'))
	{
		if (headers)
			error("403 Not a CGI path");
		else
			printf("[Not a CGI path]\n");
		goto END;
	}

	strncpy(name, file + size + 1, XS_PATH_MAX - 64);
	name[XS_PATH_MAX - 64] = 0;
	argv1 = NULL;
	if ((temp = strchr(name, '?')))
	{
		*(temp++) = 0;
		setenv("QUERY_STRING", temp, 1);
		if (!strchr(temp, '='))
			argv1 = temp;
	}

	nextslash = name;
	for (;;)
	{
		if (!(nextslash = strchr(nextslash, '/')))
			break;
		*nextslash = 0;
		sprintf(fullpath, "%s%s", base, name);
		if (stat(fullpath, &statbuf))
		{
			if (headers)
				error("403 Nonexistent CGI binary");
			else
				printf("[Nonexistent CGI binary]\n");
			goto END;
		}
		if ((statbuf.st_mode & S_IFMT) == S_IFREG)
			break;
		*(nextslash++) = '/';
	}
#if 0
	/* I don't get this part --johans */
	if (nextslash)
	{
		*nextslash = '/';
		setenv("PATH_INFO", nextslash, 1);
		setenv("PATH_TRANSLATED", convertpath(nextslash), 1);
		*nextslash = 0;
	}
#endif

	if (strstr(name, "..") || strstr(name, "/.x"))
	{
		if (headers)
			error("400 Invalid URI");
		else
			printf("[Invalid URI]\n");
		goto END;
	}
#ifdef		SUPPORT_PHP3
	if (php3)
	{
		if (userinfo)
			sprintf(fullpath, "/~%s/%s", userinfo->pw_name, name);
		else
			sprintf(fullpath, "/%s", name);
	}
	else
#endif		/* SUPPORT_PHP3 */
	if (userinfo)
		sprintf(fullpath, "/~%s/%s/%s", userinfo->pw_name,
			HTTPD_SCRIPT_ROOT, name);
	else
		sprintf(fullpath, "/%s/%s", HTTPD_SCRIPT_ROOT, name);
	if (was_slash)
	{
		setenv("SCRIPT_NAME", "/", 1);
		setenv("PATH_INFO", "/", 1);
		setenv("PATH_TRANSLATED", convertpath("/"), 1);
	}
	else
	{
		setenv("SCRIPT_NAME", fullpath, 1);
		setenv("PATH_INFO", fullpath, 1);
		setenv("PATH_TRANSLATED", convertpath(fullpath), 1);
	}

	if (headers)
	{
		sprintf(fullpath, "%s%s", base, name);
		if ((nextslash = strrchr(fullpath, '/')))
		{
			strcpy(nextslash + 1, AUTHFILE);
			if ((auth = fopen(fullpath, "r")))
			{
				if (check_auth(auth))
					goto END;
			}
		}
	}
					
	sprintf(fullpath, "%s%s", base, name);
	if (stat(fullpath, &statbuf))
	{
		if (headers)
		{
			sprintf(errmsg, "403 Cannot stat(`%s'): %s",
				fullpath, strerror(errno));
			error(errmsg);
		} else
			printf("[Cannot stat(`%s'): %s]\n",
				fullpath, strerror(errno));
		goto END;
	}
	if (statbuf.st_mode & (S_IWGRP | S_IWOTH))
	{
		if (headers)
		{
			sprintf(errmsg, "403 `%s' is writable", fullpath);
			error(errmsg);
		} else
			printf("[`%s' is writable]\n", fullpath);
		goto END;
	}
	if (userinfo && (statbuf.st_uid != currentuid))
	{
		if (headers)
		{
			sprintf(errmsg, "403 Invalid owner for `%s'", fullpath);
			error(errmsg);
		} else
			printf("[Invalid owner for `%s']\n", fullpath);
		goto END;
	}
	nph = (!strncmp(name, "nph-", 4) || strstr(name, "/nph-"));
	nouid = (strstr(name, "/nph-nid-") || strstr(name, "/nid-") ||
		!strncmp(name, "nph-nid-", 8) || !strncmp(name, "nid-", 4));
	p[0] = -1; p[1] = -1;
	if (!nph)
	{
		if (pipe(p))
		{
			sprintf(errmsg, "500 pipe() failed: %s", strerror(errno));
			if (headers)
				error(errmsg);
			else
				printf("[%s]\n", errmsg);
			goto END;
		}
	}
	switch(child = fork())
	{
	case -1:
		sprintf(errmsg, "500 fork() failed: %s", strerror(errno));
		if (headers)
			error(errmsg);
		else
			printf("[%s]\n", errmsg);
		goto END;
	case 0:
#ifndef		DONT_USE_SETRLIMIT
#ifdef		RLIMIT_CPU
		limits.rlim_cur = 120; limits.rlim_max = 128;
		setrlimit(RLIMIT_CPU, &limits);
#endif		/* RLIMIT_CPU */
#ifdef		RLIMIT_CORE
		limits.rlim_cur = limits.rlim_max = 0;
		setrlimit(RLIMIT_CORE, &limits);
#endif		/* RLIMIT_CORE */
#ifdef		RLIMIT_MEMLOCK
		limits.rlim_cur = limits.rlim_max = 1;
		setrlimit(RLIMIT_MEMLOCK, &limits);
#endif		/* RLIMIT_MEMLOCK */
#endif		/* DONT_USE_SETRLIMIT */

		if (!nph)
			dup2(p[1], 1);

#ifdef		HAVE_SETSID
		if (setsid() == -1)
		{
			printf("Content-type: text/plain\r\n\r\n");
			printf("[setsid() failed]\n");
			exit(1);
		}
#else		/* Not HAVE_SETSID */
		if (setpgrp(getpid(), 0)) == -1)
		{
			printf("Content-type: text/plain\r\n\r\n");
			printf("[setpgrp() failed]\n");
			exit(1);
		}
#endif		/* HAVE_SETSID */

		for (count = 3; count < 64; count++)
			close(count);
		if (!origeuid)
		{
			seteuid(origeuid);
			if (nouid)
			{
				currentuid = user_id;
				currentgid = group_id;
			}
			setgid(currentgid); setuid(currentuid);
			if (!getuid() || !geteuid() ||
				(getuid() != currentuid) ||
				(getgid() != currentgid))
			{
				printf("Content-type: text/plain\r\n\r\n");
				printf("[Invalid UID setting]\n");
				printf("UID = %ld, EUID = %ld\n",
					(long)getuid(), (long)geteuid());
				exit(1);
			}
		}
		setenv("PATH", SCRIPT_PATH, 1);
		if (chdir(base))
		{
			printf("Content-type: text/plain\r\n\r\n");
			printf("[Cannot change directory]\n");
			exit(1);
		}
#ifdef		SUPPORT_PHP3
		if (php3)
		{
			/* PHP's CGI mode sucks big time */
			unsetenv("SERVER_SOFTWARE"); unsetenv("SERVER_NAME");
			unsetenv("GATEWAY_INTERFACE"); unsetenv("REQUEST_METHOD");
			execl(PHP3_PATH, "php", fullpath, argv1, NULL);
		}
		else
#endif		/* SUPPORT_PHP3 */
		execl(fullpath, name, argv1, NULL);
		if (nph)
		{
			sprintf(errmsg, "500 execl(`%s'): %s",
				fullpath, strerror(errno));
			error(errmsg);
		} else
		{
			printf("Content-type: text/plain\r\n\r\n");
			printf("[execl(`%s') failed: %s",
				fullpath, strerror(errno));
		}
		exit(1);
	default:
		close(p[1]);
		break;
	}
	if (nph)
		exit(0);

	status[0] = contenttype[0] = location[0] = cachecontrol[0] = 0;
	netbufind = netbufsiz = 0; readlinemode = 1;
	if (!nph)
	{
		while (1)
		{
			if (readline(p[0], errmsg) != ERR_NONE)
			{
				if (headers)
					error("503 Script did not end header");
				else
					printf("[Script did not end header]\n");
				goto END;
			}
			received = strlen(errmsg);
			while ((received > 0) && (errmsg[received - 1] < 32))
				errmsg[--received] = 0;
			header = skipspaces(errmsg);
			if (!header[0])
				break;
			if (!strncasecmp(header, "Status:", 7))
				strcpy(status, skipspaces(header + 7));
			else if (!strncasecmp(header, "Location:", 9))
				strcpy(location, skipspaces(header + 9));
			else if (!strncasecmp(header, "Content-type:", 13))
				strcpy(contenttype, skipspaces(header + 13));
			else if (!strncasecmp(header, "Cache-control:", 14))
				strcpy(cachecontrol, skipspaces(header + 14));
			else if (!strncasecmp(header, "Set-cookie:", 11))
				strcpy(cachecontrol, skipspaces(header + 11));
			else
			{
				fprintf(stderr, "[%s] httpd: Invalid header `%s' from script `%s'\n",
					currenttime, header, name);
				if (headers)
					error("503 Script gave invalid header");
				else
					printf("[Script gave invalid header]\n");
				goto END;
			}
		}
		if (headers)
		{
			printf("%s %s\r\n", version, status[0] ? status :
				(location[0] ? "302 Moved" : "200 OK"));
			printf("Content-type: %s\r\n",
				(!contenttype[0]) ? "text/html" : contenttype);
			if (cachecontrol[0])
			{
				if (headers >= 11)
					printf("Cache-control: %s\r\n", cachecontrol);
				else
					printf("Pragma: no-cache\r\n");
			}
			switch(location[0])
			{
			case '/':
				if (port == 80)
					printf("Location: http://%s%s\r\n",
						thishostname, location);
				else
					printf("Location: http://%s:%d%s\r\n",
						thishostname, port, location);
				break;
			case 0:
				break;
			default:
				printf("Location: %s\r\n", location);
				break;
			}
			setcurrenttime();
			printf("Date: %s\r\nLast-modified: %s\r\n",
				currenttime, currenttime);
			printf("Server: %s\r\n\r\n", SERVER_IDENT);
		} else
		{
			if (location[0])
				printf("[Internal `location' not supported]\n");
		}
	} else
	{
		while (1)
		{
			if (readline(p[0], errmsg) != ERR_NONE)
			{
				if (headers)
					error("503 Script did not end header");
				else
					printf("[Script did not end header]\n");
				goto END;
			}
			received = strlen(errmsg);
			if (headers)
				printf("%s", errmsg);
			while ((received > 0) && (errmsg[received - 1] < 32))
				errmsg[--received] = 0;
			if (!errmsg[0])
				break;
		}
	}
	fflush(stdout);
	if ((totalwritten = netbufsiz - netbufind) > 0)
	{
		writetodo = totalwritten; temp = netbuf + netbufind;
		while (writetodo > 0)
		{
			switch(written = write(fileno(stdout), temp, writetodo))
			{
			case -1:
				if (errno == EINTR)
					break;
				printf("[Connection closed: %s (fd = %d, temp = %p, todo = %ld]\n",
					strerror(errno), fileno(stdout), temp,
					writetodo);
				goto END;
			case 0:
				printf("[Connection closed: couldn't write]\n");
				goto END;
			default:
				writetodo -= written;
				temp += written;
			}
		}
	}

	for (;;)
	{
		received = read(p[0], errmsg, MYBUFSIZ);
		if (received == -1)
		{
			if (errno == EINTR)
				continue;
			printf("[read() error from CGI: %s]", strerror(errno));
			break;
		} else if (received == 0)
			break;
		writetodo = received; temp = errmsg;
		while (writetodo > 0)
		{
			switch(written = write(fileno(stdout), temp, writetodo))
			{
			case -1:
				if (errno == EINTR)
					break;
				printf("[Connection closed: %s (fd = %d, temp = %p, todo = %ld]\n",
					strerror(errno), fileno(stdout), temp,
					writetodo);
				goto END;
			case 0:
				printf("[Connection closed: couldn't write]\n");
				goto END;
			default:
				writetodo -= written;
				temp += written;
			}
		}
		totalwritten += received;
	}

	{
		char		buffer[80];
		time_t		theclock;

		time(&theclock);
		strftime(buffer, 80, "%d/%b/%Y:%H:%M:%S", localtime(&theclock));
		fprintf(access_log, "%s - - [%s +0000] \"%s %s %s\" 200 %ld\n",
			remotehost, buffer, getenv("REQUEST_METHOD"), path,
			version, totalwritten > 0 ? totalwritten : (long)0);
	}
	END:
	close(p[0]); close(p[1]); fflush(stdout);
	if (!origeuid)
	{
		seteuid(origeuid); setegid(savedegid); seteuid(savedeuid);
	}
#ifdef		HAVE_SIGEMPTYSET
	sigemptyset(&action.sa_mask);
#else		/* Not HAVE_SIGEMPYSET */
	action.sa_mask = 0;
#endif		/* HAVE_SIGEMPTYSET */
	action.sa_handler = alarm_handler;
	action.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);
	/* alarm(left); */
}
