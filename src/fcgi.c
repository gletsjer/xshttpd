/* Copyright (C) 2006 by Remko van der Vossen (wich@stack.nl) */
/* Copyright (C) 2006 by Johan van Selst (johans@stack.nl) */

#include "config.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>

#include "ssl.h"
#include "fcgi_api.h"
#include "fcgi.h"
#include "htconfig.h"
#include "malloc.h"
#include "alternative.h"

#ifndef		PF_LOCAL
#define	PF_LOCAL	PF_UNIX
#endif				/* PF_LOCAL */

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
static pid_t		*fcgichildren = NULL;

int		fcgi_connect(fcgi_server * server);
void		fcgi_disconnect(fcgi_server * server);
void		begin_request(fcgi_server * server);
int		fcgi_child_init(void);
int		init_env(fcgi_env * fenv);
void		free_env(fcgi_env * fenv);
int		set_env(fcgi_env * fenv, const char *name, const char *value);
void		build_env(fcgi_env * fenv);
int		send_env(fcgi_server * server, fcgi_env * fenv);
int		handle_record(fcgi_server * server, int, int);
ssize_t		send_stream(fcgi_server * server, off_t length, unsigned char stream_id, int fd);
ssize_t		recv_stream(fcgi_server * server, off_t length, int fd);

int
run_fcgi(int fdin, int fdout, int fderr)
{
	fcgi_env	fenv;
	int		request_ended = 0;
	off_t		content_length = 0;
	fcgi_server	*server = current->fcgiserver;

	if (!server)
		return -1;

	if (getenv("CONTENT_LENGTH"))
		content_length = (off_t)strtoull(getenv("CONTENT_LENGTH"),
			NULL, 10);
	init_env(&fenv);
	build_env(&fenv);
	write(fdout, "X-FastCGI: 1\r\n", 14);

	fcgi_connect(server);
	begin_request(server);
	send_env(server, &fenv);
	if (!content_length)
		send_stream(server, 0, FCGI_STDIN, STDIN_FILENO);
	/*
	 * if (empty data file)
	 * 	send_stream(&server, 0, FCGI_DATA, data_file);
	 */

	while (!request_ended)
	{
		fd_set		set;
		int		ret;

		FD_ZERO(&set);
		FD_SET(server->socket, &set);
		/*
		 * if (content_length)
		 * 	FD_SET(STDIN_FILENO, &set);
		 * if (...)
		 * 	FD_SET(data_file, &set);
		 */

		ret = select(server->socket + 1, &set, NULL, NULL, 0);

		if (FD_ISSET(server->socket, &set))
		{
			switch (handle_record(server, fdout, fderr))
			{
			case FCGI_END_REQUEST:
				request_ended = 1;
				break;
			}
		}
		if (FD_ISSET(STDIN_FILENO, &set))
		{
			ssize_t		n;
			n = send_stream(server, content_length, FCGI_STDIN, STDIN_FILENO);

			if (n <= 0 || n > content_length)
			{
			}
			content_length -= n;
			if (!content_length)
			{
				send_stream(server, (off_t)0, FCGI_STDIN, STDIN_FILENO);
			}
		}
		/*
		 * if (... && FD_ISSET(data_file, &set))
		 * {
		 * 	ssite_t n =
		 * 		send_stream(&server, ..., FCGI_DATA, data_file);
		 * 	if (n <= 0) { }
		 * 	if (...)
		 * 		send_stream(&server, 0, FCGI_DATA, data_file);
		 * }
		 */
	}

	fcgi_disconnect(server);
	free_env(&fenv);
	return 0;
}

int 
fcgi_child_init(void)
{
	pid_t		child;
	const int	argv_sz = 32;
	char		*argv[32], buf[16];
	char		*sep, *str, **ap;
	fcgi_server	*fsrv;

	MALLOC(fsrv, fcgi_server, 1);
	if (!current->fcgisocket)
		return -1;

	current->fcgiserver = fsrv;
	if ((sep = strchr(current->fcgisocket, ':')))
	{
		*sep = '\0';
		fsrv->type = FCGI_INET_SOCKET;
		STRDUP(fsrv->host, current->fcgisocket);
		STRDUP(fsrv->port, sep + 1);
		*sep = ':';
	}
	else
	{
		fsrv->type = FCGI_UNIX_SOCKET;
		STRDUP(fsrv->unixsocket, current->fcgisocket);
	}

	if (!current->fcgipath)
		return 0;

	str = current->fcgipath;
	for (ap = argv; (*ap = strsep(&str, " \t")) != NULL;)
		if (**ap)
		{
			if (!strcmp(*ap, "%s"))
				*ap = current->fcgisocket;
			if (++ap >= &argv[argv_sz])
			{
				argv[argv_sz - 1] = NULL;
				break;
			}
		}

	switch (child = fork())
	{
	case -1:
		return -1;
	case 0:
		setegid(current->groupid);
		setgid(current->groupid);
		seteuid(current->userid);
		setuid(current->userid);
		setenv("FCGI_WEB_SERVER_ADDRS", "127.0.0.1", 1);
		if (current->phpfcgichildren)
		{
			snprintf(buf, sizeof buf, "%u",
				current->phpfcgichildren);
			setenv("PHP_FCGI_CHILDREN", buf, 1);
		}
		else
			setenv("PHP_FCGI_CHILDREN", "16", 1);
		if (current->phpfcgirequests)
		{
			snprintf(buf, sizeof buf, "%u",
				current->phpfcgirequests);
			setenv("PHP_FCGI_MAX_REQUESTS", buf, 1);
		}
		else
			setenv("PHP_FCGI_MAX_REQUESTS", "2000", 1);

		execv(argv[0], argv);
		exit(1);
	default:
		return child;
	}
	/* NOTREACHED */
}

void
initfcgi(void)
{
	int     cnt, fcginum, ret;

	fcginum = 0;
	fcgichildren = NULL;
	for (current = config.virtual; current; current = current->next)
		fcginum++;

	if (!fcginum)
		return;
	MALLOC(fcgichildren, pid_t, fcginum + 1);

	cnt = 0;
	for (current = config.virtual; current; current = current->next)
		if (current->fcgisocket)
		{
			if ((ret = fcgi_child_init()) > 0)
				fcgichildren[cnt++] = ret;
			else
				err(1, "fcgi_init() failed");
		}
	fcgichildren[cnt] = 0;
}

void
killfcgi(void)
{
	if (fcgichildren)
		for (pid_t * pid = fcgichildren; *pid > 0; pid++)
			kill(*pid, SIGTERM);
}

int 
fcgi_connect(fcgi_server *server)
{
	struct sockaddr		*addr;
	struct sockaddr_un	addr_un;
	struct addrinfo		*info, hints;
	socklen_t		len;

	switch (server->type)
	{
	case FCGI_UNIX_SOCKET:
	default:
		memset(&addr_un, 0, sizeof(addr_un));
		addr_un.sun_family = AF_UNIX;
		strcpy(addr_un.sun_path, server->unixsocket);
		addr = (struct sockaddr *)&addr_un;
		len = sizeof(unsigned char) + sizeof(sa_family_t)
			+ strlen(server->unixsocket) + 1;
		server->socket = socket(PF_LOCAL, SOCK_STREAM, 0);
		break;
	case FCGI_INET_SOCKET:
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_INET;
		hints.ai_socktype = SOCK_STREAM;
		if (0 != getaddrinfo(server->host, server->port, &hints, &info))
		{
			return -1;
		}
		addr = info->ai_addr;
		len = info->ai_addrlen;
		server->socket = socket(PF_INET, SOCK_STREAM, 0);
		break;
	}

	if (-1 == server->socket)
	{
		return -1;
	}

	if (-1 == connect(server->socket, addr, len))
	{
		return -1;
	}

	if (server->type == FCGI_INET_SOCKET)
		freeaddrinfo(info);

	return 0;
}

void 
fcgi_disconnect(fcgi_server * server)
{
	close(server->socket);
	server->socket = -1;
}

void 
begin_request(fcgi_server * server)
{
	FCGI_record	record_header;
	FCGI_begin	begin_header;

	memset(&record_header, 0, sizeof(record_header));
	memset(&begin_header, 0, sizeof(begin_header));

	record_header.version = FCGI_VERSION_1;
	record_header.type = FCGI_BEGIN_REQUEST;
	record_header.request_id_0 = 1;
	record_header.content_length_0 = sizeof(begin_header);
	begin_header.role_0 = FCGI_RESPONDER;
	begin_header.flags = 0;

	write(server->socket, &record_header, sizeof(record_header));
	write(server->socket, &begin_header, sizeof(begin_header));
}

int 
init_env(fcgi_env * fenv)
{
	fenv->buffer_size = 1024;
	fenv->env_size = 0;
	MALLOC(fenv->buffer, char, fenv->buffer_size);
	return 0;
}

void 
free_env(fcgi_env * fenv)
{
	free(fenv->buffer);
	fenv->buffer = NULL;
	fenv->buffer_size = 0;
	fenv->env_size = 0;
}

int 
set_env(fcgi_env * fenv, const char *name, const char *value)
{
	size_t		name_len = strlen(name);
	size_t		value_len = strlen(value);
	int		pair_type = 0;
	char		*p;

	if (!value)
		return -1;

	if (name_len > 127)
		pair_type |= FCGI_PAIR_LONG_NAME;
	if (value_len > 127)
		pair_type |= FCGI_PAIR_LONG_VALUE;

	if (fenv->env_size + 8 + name_len + value_len < fenv->buffer_size)
	{
		fenv->buffer_size += MAX(1024, 8 + name_len + value_len);
		REALLOC(fenv->buffer, char, fenv->buffer_size);
	}

	p = fenv->buffer + fenv->env_size;

	switch (pair_type)
	{
	case FCGI_PAIR_TYPE_11:
		memset(p, 0, sizeof(FCGI_name_value_pair_11));
		((FCGI_name_value_pair_11 *) p)->name_length = name_len;
		((FCGI_name_value_pair_11 *) p)->value_length = value_len;
		p += sizeof(FCGI_name_value_pair_11);
		break;
	case FCGI_PAIR_TYPE_14:
		memset(p, 0, sizeof(FCGI_name_value_pair_14));
		((FCGI_name_value_pair_14 *) p)->name_length = name_len;
		((FCGI_name_value_pair_14 *) p)->value_length_0 = value_len & 0xff;
		((FCGI_name_value_pair_14 *) p)->value_length_1 = (value_len >> 8) & 0xff;
		((FCGI_name_value_pair_14 *) p)->value_length_2 = (value_len >> 16) & 0xff;
		((FCGI_name_value_pair_14 *) p)->value_length_3 = 0x80 | ((value_len >> 24) & 0x7f);
		p += sizeof(FCGI_name_value_pair_14);
		break;
	case FCGI_PAIR_TYPE_41:
		memset(p, 0, sizeof(FCGI_name_value_pair_41));
		((FCGI_name_value_pair_41 *) p)->name_length_0 = name_len & 0xff;
		((FCGI_name_value_pair_41 *) p)->name_length_1 = (name_len >> 8) & 0xff;
		((FCGI_name_value_pair_41 *) p)->name_length_2 = (name_len >> 16) & 0xff;
		((FCGI_name_value_pair_41 *) p)->name_length_3 = 0x80 | ((name_len >> 24) & 0x7f);
		((FCGI_name_value_pair_41 *) p)->value_length = value_len;
		p += sizeof(FCGI_name_value_pair_41);
		break;
	case FCGI_PAIR_TYPE_44:
		memset(p, 0, sizeof(FCGI_name_value_pair_44));
		((FCGI_name_value_pair_44 *) p)->name_length_0 = name_len & 0xff;
		((FCGI_name_value_pair_44 *) p)->name_length_1 = (name_len >> 8) & 0xff;
		((FCGI_name_value_pair_44 *) p)->name_length_2 = (name_len >> 16) & 0xff;
		((FCGI_name_value_pair_44 *) p)->name_length_3 = 0x80 | ((name_len >> 24) & 0x7f);
		((FCGI_name_value_pair_44 *) p)->value_length_0 = value_len & 0xff;
		((FCGI_name_value_pair_44 *) p)->value_length_1 = (value_len >> 8) & 0xff;
		((FCGI_name_value_pair_44 *) p)->value_length_2 = (value_len >> 16) & 0xff;
		((FCGI_name_value_pair_44 *) p)->value_length_3 = 0x80 | ((value_len >> 24) & 0x7f);
		p += sizeof(FCGI_name_value_pair_44);
		break;
	}

	memcpy(p, name, name_len);
	p += name_len;
	memcpy(p, value, value_len);
	p += value_len;

	fenv->env_size = p - fenv->buffer;
	return 0;
}

void 
build_env(fcgi_env * fenv)
{
	char	*c, **p;

	for (p = environ; *p; p++)
		if ((c = strchr(*p, '=')))
		{
			*c = '\0';
			set_env(fenv, *p, c + 1);
			*c = '=';
		}
	/* FIXME - return values not handled */
}

int 
send_env(fcgi_server * server, fcgi_env * fenv)
{
	FCGI_record	record_header;

	char	*p = fenv->buffer;
	char	*q = fenv->buffer + fenv->env_size;

	memset(&record_header, 0, sizeof(record_header));

	record_header.version = FCGI_VERSION_1;
	record_header.type = FCGI_PARAMS;
	record_header.request_id_0 = 1;

	while (p != q)
	{
		ptrdiff_t	n = MIN(FCGI_MAX_BUFFER, q - p);

		record_header.content_length_0 = n & 0xff;
		record_header.content_length_1 = (n >> 8) & 0xff;
		if (sizeof(record_header) !=
			write(server->socket, &record_header, sizeof(record_header)))
		{
			return -1;
		}
		if (n != write(server->socket, p, n))
		{
			return -1;
		}
		p += n;
	}

	record_header.content_length_0 = 0;
	record_header.content_length_1 = 0;
	if (sizeof(record_header) !=
		write(server->socket, &record_header, sizeof(record_header)))
	{
		return -1;
	}

	return 0;
}

int 
handle_record(fcgi_server * server, int fdout, int fderr)
{
	FCGI_record	record_header;
	off_t		content_length = 0;
	char		padding   [255];
	int		bytes;

	if (sizeof(record_header) !=
		(bytes = read(server->socket, &record_header, sizeof(record_header))))
	{
		return -1;
	}

	content_length = record_header.content_length_1 << 8 |
		record_header.content_length_0;

	switch (record_header.type)
	{
	case FCGI_END_REQUEST:
		break;
	case FCGI_STDOUT:
		recv_stream(server, content_length, fdout);
		break;
	case FCGI_STDERR:
		recv_stream(server, content_length, fderr);
		break;
	case FCGI_GET_VALUES_RESULT:
		/* don't use it so break */
		break;
	case FCGI_UNKNOWN_TYPE:
		/* ... */
		return -1;
		break;
	default:
		/* should not get any other type */
		return -1;
		break;
	}

	if (record_header.padding_length !=
	    read(server->socket, &padding, record_header.padding_length))
	{
		return -1;
	}

	return record_header.type;
}

ssize_t 
send_stream(fcgi_server * server, off_t length, unsigned char stream_id, int fd)
{
	FCGI_record	record_header;
	char		*buffer = NULL;
	char		padding   [7];
	ssize_t		n;

	n = MIN(FCGI_MAX_BUFFER, length);

	MALLOC(buffer, char, n);

	if (n <= 0)
	{
		free(buffer);
		return -1;
	}

	memset(&record_header, 0, sizeof(record_header));

	record_header.version = FCGI_VERSION_1;
	record_header.type = stream_id;
	record_header.request_id_0 = 1;
	record_header.content_length_0 = n & 0xff;
	record_header.content_length_1 = (n >> 8) & 0xff;
	record_header.padding_length = n & 0x07 ? (~n & 0x07) + 1 : 0;

	if (sizeof(record_header) !=
	    write(server->socket, &record_header, sizeof(record_header)))
	{
		free(buffer);
		return -1;
	}
	if (n != write(server->socket, buffer, n))
	{
		free(buffer);
		return -1;
	}
	if (record_header.padding_length !=
	    write(server->socket, &padding, record_header.padding_length))
	{
		free(buffer);
		return -1;
	}

	free(buffer);
	return n;
}

ssize_t 
recv_stream(fcgi_server * server, off_t length, int fd)
{
	char		*buffer = NULL;
	ssize_t		n;

	if (length <= 0 || length > INT_MAX)
		return 0;

	MALLOC(buffer, char, length);

	n = read(server->socket, buffer, length);

	if (n <= 0)
	{
		free(buffer);
		return -1;
	}

	if (n != write(fd, buffer, n))
	{
		free(buffer);
		return -1;
	}

	free(buffer);
	return n;
}
