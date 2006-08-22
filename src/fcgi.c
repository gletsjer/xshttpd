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

#include "htconfig.h"
#include "ssl.h"
#include "setenv.h"
#include "fcgi_api.h"
#include "fcgi.h"

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
fcgi_server	fsrv;

int  fcgi_connect(fcgi_server* server);
void fcgi_disconnect(fcgi_server* server);
void begin_request(fcgi_server* server);
int  init_env(fcgi_env* env);
void free_env(fcgi_env* env);
int  set_env(fcgi_env* env, const char* name, const char* value);
void build_env(fcgi_env* env);
int  send_env(fcgi_server* server, fcgi_env* env);
int  handle_record(fcgi_server* server);
ssize_t send_stream(fcgi_server* server, ssize_t length, unsigned char stream_id, int fd);
ssize_t recv_stream(fcgi_server* server, ssize_t length, int fd); 

void 
do_fcgi(const char *path, const char *base, const char *file, int showheader) {
	fcgi_env env;
	int request_ended = 0;
	ssize_t content_length = atoi(getenv("CONTENT_LENGTH"));
	char fullpath[XS_PATH_MAX];
	fcgi_server *server = &fsrv;
	snprintf(fullpath, XS_PATH_MAX, "%s%s", base, file);

	(void)showheader;
	init_env(&env);
	/* FIXME need webserver address list*/
	setenv("FCGI_WEBSERVER_ADDRS", "131.155.141.70", 1);
	build_env(&env);
	setenv("SCRIPT_NAME", path, 1);
	setenv("SCRIPT_FILENAME", fullpath, 1);
	setenv("REDIRECT_STATUS", "200", 1);
	setenv("PATH", config.scriptpath, 1);
	secwrite("HTTP/1.0 200 OK\r\n", 17);
	
	fcgi_connect(server);
	begin_request(server);
	send_env(server, &env);
	if (!content_length)
		send_stream(server, 0, FCGI_STDIN, STDIN_FILENO);
	/*
	if (empty data file)
		send_stream(&server, 0, FCGI_DATA, data_file);
	*/
	
	while (!request_ended) {
		fd_set set;
		int	ret;

		FD_ZERO(&set);
		FD_SET(server->socket, &set);
		/*
		if (content_length)
		  FD_SET(STDIN_FILENO, &set);
		if (...)
			FD_SET(data_file, &set);
		*/

		ret = select(server->socket + 1, &set, NULL, NULL, 0);
		
		if (FD_ISSET(server->socket, &set)) {	
			switch (handle_record(server)) {
				case FCGI_END_REQUEST:
					request_ended = 1;
					break;
			}
		}
		if (FD_ISSET(STDIN_FILENO, &set)) {
			ssize_t n = send_stream(server, content_length, FCGI_STDIN, STDIN_FILENO);
			if (n <= 0 || n > content_length) {
			}
			content_length -= n;
			if (!content_length) {
				send_stream(server, 0, FCGI_STDIN, STDIN_FILENO);
			}
		}
		/*
		if (... && FD_ISSET(data_file, &set)) {
			ssite_t n = send_stream(&server, ..., FCGI_DATA, data_file);
			if (n <= 0) {
			}
			if (...) {
				send_stream(&server, 0, FCGI_DATA, data_file);
			}
		*/
	}

	fcgi_disconnect(server);
	free_env(&env);
}

int fcgi_init(const char *path, const char *host, const char *port) {
	if (path && host)
		return -1;
	if (path)
	{
		fsrv.type = FCGI_UNIX_SOCKET;
		fsrv.unixsocket = strdup(path);
	}
	else if (host)
	{
		fsrv.type = FCGI_INET_SOCKET;
		fsrv.host = strdup(host);
		fsrv.port = strdup(port);
	}
	else
		return -1;
	return 0;
}

int fcgi_connect(fcgi_server* server) {
	struct sockaddr* addr;
	struct sockaddr_un addr_un;
	struct addrinfo* info, hints;
	socklen_t len;

	switch (server->type) {
		case FCGI_UNIX_SOCKET:
		default:
			memset(&addr_un, 0, sizeof(addr_un));
			addr_un.sun_family = AF_UNIX;
			strcpy(addr_un.sun_path, server->unixsocket);
			addr = (struct sockaddr*)&addr_un;
			len = sizeof(unsigned char) + sizeof(sa_family_t)
			      + strlen(server->unixsocket) + 1;
			server->socket = socket(PF_LOCAL, SOCK_STREAM, 0);
			break;
		case FCGI_INET_SOCKET:
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_INET;
			hints.ai_socktype = SOCK_STREAM;
			if (0 != getaddrinfo(server->host, server->port, &hints, &info)) {
				return -1;
			}
			addr = info->ai_addr;
			len = info->ai_addrlen;
			server->socket = socket(PF_INET,  SOCK_STREAM, 0);
			break;
	}

	if (-1 == server->socket) {
		return -1;
	}

	if (-1 == connect(server->socket, addr, len)) {
		return -1;
	}	

	if (server->type == FCGI_INET_SOCKET)
		freeaddrinfo(info);

	return 0;
}

void fcgi_disconnect(fcgi_server* server) {
	close(server->socket);
	server->socket = -1;
}

void begin_request(fcgi_server* server) {
	FCGI_record record_header;
	FCGI_begin  begin_header;

	memset(&record_header, 0, sizeof(record_header));
	memset(&begin_header,  0, sizeof(begin_header) );
	
	record_header.version          = FCGI_VERSION_1;
	record_header.type             = FCGI_BEGIN_REQUEST;
	record_header.request_id_0     = 1;
	record_header.content_length_0 = sizeof(begin_header);
	begin_header.role_0            = FCGI_RESPONDER;
	begin_header.flags             = 0;

	write(server->socket, &record_header, sizeof(record_header));
	write(server->socket, &begin_header, sizeof(begin_header));
}

int init_env(fcgi_env* env) {
	env->buffer_size = 1024; 
	env->env_size = 0;
	env->buffer = (char*)malloc(env->buffer_size);
	if (env->buffer == NULL)
		return -1;
	return 0;
}

void free_env(fcgi_env* env) {
	free(env->buffer);
	env->buffer = NULL;
	env->buffer_size = 0;
	env->env_size = 0;
}

int set_env(fcgi_env* env, const char* name, const char* value) {
	size_t name_len  = strlen(name);
	size_t value_len = strlen(value);
	int pair_type = 0;
	char	*p;

	if (!value)
		return -1;

	if (name_len > 127)
		pair_type |= FCGI_PAIR_LONG_NAME;
	if (value_len > 127)
		pair_type |= FCGI_PAIR_LONG_VALUE;
	
	if (env->env_size + 8 + name_len + value_len < env->buffer_size) {
		env->buffer_size += MAX(1024, 8 + name_len + value_len);
		env->buffer = (char*)realloc(env->buffer, env->buffer_size);
		if (NULL == env->buffer) {
			return -1;
		}
	}
	
	p = env->buffer + env->env_size;
	
	switch (pair_type) {
		case FCGI_PAIR_TYPE_11:
			memset(p, 0, sizeof(FCGI_name_value_pair_11));
			((FCGI_name_value_pair_11*)p)->name_length    =         name_len;
			((FCGI_name_value_pair_11*)p)->value_length   =         value_len;
			p += sizeof(FCGI_name_value_pair_11);
			break;
		case FCGI_PAIR_TYPE_14:
			memset(p, 0, sizeof(FCGI_name_value_pair_14));
			((FCGI_name_value_pair_14*)p)->name_length    =         name_len;
			((FCGI_name_value_pair_14*)p)->value_length_0 =         value_len        & 0xff;
			((FCGI_name_value_pair_14*)p)->value_length_1 =        (value_len >>  8) & 0xff;
			((FCGI_name_value_pair_14*)p)->value_length_2 =        (value_len >> 16) & 0xff;
			((FCGI_name_value_pair_14*)p)->value_length_3 = 0x80 | (value_len >> 24) & 0x7f;
			p += sizeof(FCGI_name_value_pair_14);
			break;
		case FCGI_PAIR_TYPE_41:
			memset(p, 0, sizeof(FCGI_name_value_pair_41));
			((FCGI_name_value_pair_41*)p)->name_length_0  =         name_len         & 0xff;
			((FCGI_name_value_pair_41*)p)->name_length_1  =        (name_len  >>  8) & 0xff;
			((FCGI_name_value_pair_41*)p)->name_length_2  =        (name_len  >> 16) & 0xff;
			((FCGI_name_value_pair_41*)p)->name_length_3  = 0x80 | (name_len  >> 24) & 0x7f;
			((FCGI_name_value_pair_41*)p)->value_length   =         value_len;
			p += sizeof(FCGI_name_value_pair_41);
			break;
		case FCGI_PAIR_TYPE_44:
			memset(p, 0, sizeof(FCGI_name_value_pair_44));
			((FCGI_name_value_pair_44*)p)->name_length_0  =         name_len         & 0xff;
			((FCGI_name_value_pair_44*)p)->name_length_1  =        (name_len  >>  8) & 0xff;
			((FCGI_name_value_pair_44*)p)->name_length_2  =        (name_len  >> 16) & 0xff;
			((FCGI_name_value_pair_44*)p)->name_length_3  = 0x80 | (name_len  >> 24) & 0x7f;
			((FCGI_name_value_pair_44*)p)->value_length_0 =         value_len        & 0xff;
			((FCGI_name_value_pair_44*)p)->value_length_1 =        (value_len >>  8) & 0xff;
			((FCGI_name_value_pair_44*)p)->value_length_2 =        (value_len >> 16) & 0xff;
			((FCGI_name_value_pair_44*)p)->value_length_3 = 0x80 | (value_len >> 24) & 0x7f;
			p += sizeof(FCGI_name_value_pair_44);
			break;
	}

	memcpy(p, name,  name_len);
	p += name_len;
	memcpy(p, value, value_len);
	p += value_len;

	env->env_size = p - env->buffer;
	return 0;
}

void build_env(fcgi_env* env) {
	char	*c, **p;

	for (p = environ; *p; p++)
		if ((c = strchr(*p, '=')))
		{
			*c = '\0';
			set_env(env, *p, c + 1);
			*c = '=';
		}
	/* FIXME - return values not handled */
}

int send_env(fcgi_server* server, fcgi_env* env) {
	FCGI_record record_header;

	char *p = env->buffer;
	char *q = env->buffer + env->env_size;

	memset(&record_header, 0, sizeof(record_header));

	record_header.version      = FCGI_VERSION_1;
	record_header.type         = FCGI_PARAMS;
	record_header.request_id_0 = 1;
	
	while (p != q) {
		ptrdiff_t n = MIN(FCGI_MAX_BUFFER, q-p);
		record_header.content_length_0 =  n       & 0xff;
		record_header.content_length_1 = (n >> 8) & 0xff;
		if (sizeof(record_header) != write(server->socket, &record_header, sizeof(record_header))) {
			return -1;
		}
		if (n != write(server->socket, p, n)) {
			return -1;
		}
		p += n;
	}

	record_header.content_length_0 = 0;
	record_header.content_length_1 = 0;
	if (sizeof(record_header) != write(server->socket, &record_header, sizeof(record_header))) {
		return -1;
	}

	return 0;
}

int handle_record(fcgi_server* server) {
	FCGI_record record_header;
	ssize_t content_length = 0;
	char padding[255];
	int bytes;

	if (sizeof(record_header) != (bytes = read(server->socket, &record_header, sizeof(record_header)))) {
		return -1;	
	}

	content_length = record_header.content_length_1 << 8 | record_header.content_length_0;

	switch (record_header.type) {
		case FCGI_END_REQUEST:
			break;
		case FCGI_STDOUT:
			recv_stream(server, content_length, STDOUT_FILENO);
			break;
		case FCGI_STDERR:
			recv_stream(server, content_length, STDERR_FILENO);
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
		read(server->socket, &padding, record_header.padding_length)) {
		return -1;
	}

	return record_header.type;
}

ssize_t send_stream(fcgi_server* server, ssize_t length, unsigned char stream_id, int fd) {
	FCGI_record record_header;
	char* buffer = NULL;
	char padding[7];
	ssize_t n;

	n = MIN(FCGI_MAX_BUFFER, length);

	buffer = (char*)malloc(n);

	if (NULL == buffer) {
		return -1;
	}
	
	n = secread(fd, buffer, n);

	if (n <= 0) {
		free(buffer);
		return -1;
	}

	memset(&record_header, 0, sizeof(record_header));

	record_header.version          = FCGI_VERSION_1;
	record_header.type             = stream_id;
	record_header.request_id_0     = 1;
	record_header.content_length_0 =  n       & 0xff;
	record_header.content_length_1 = (n >> 8) & 0xff;
	record_header.padding_length   = n & 0x07 ? (~n & 0x07) + 1 : 0;

	if (sizeof(record_header) !=
		write(server->socket, &record_header, sizeof(record_header))) {
		free(buffer);
		return -1;
	}
	if (n != write(server->socket, buffer, n)) {
		free(buffer);
		return -1;
	}
	if (record_header.padding_length !=
		write(server->socket, &padding, record_header.padding_length)) {
		free(buffer);
		return -1;
	}

	free(buffer);
	return n;
}

ssize_t recv_stream(fcgi_server* server, ssize_t length, int fd) {
	char* buffer = NULL;
	ssize_t n = length;

	if (length == 0)
		return 0;

	buffer = (char*)malloc(n);

	if (NULL == buffer) {
		return -1;
	}

	n = read(server->socket, buffer, n);

	if (n <= 0) {
		free(buffer);
		return -1;
	}

	if (n != secwrite(buffer, n)) {
		free(buffer);
		return -1;
	}

	free(buffer);
	return n;
}
