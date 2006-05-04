#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "htconfig.h"
#include "ssl.h"
#include "setenv.h"
#include "fcgi.h"
#include "fcgi_api.h"

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))

int  establish_connection(fcgi_connection* connection);
void begin_request(fcgi_connection* connection);
void set_env(fcgi_env* env, char* name, char* value);
int  init_env(fcgi_env* env);
void free_env(fcgi_env* env);
void build_env(fcgi_env* env);
void send_env(fcgi_connection* connection, fcgi_env* env);
int  handle_record(fcgi_connection* connection);
ssize_t send_stream(fcgi_connection* connection, ssize_t length, int fd);
ssize_t recv_stream(fcgi_connection* connection, ssize_t length, int fd); 

void 
do_fcgi(const char *path, const char *base, const char *file, const char *engine, int showheader) {
	fcgi_connection connection;
	fcgi_env env;
	int request_ended = 0;
	ssize_t content_length = atoi(getenv("CONTENT_LENGTH"));

	init_env(&env);
	build_env(&env);
	set_env(env, "SCRIPT_NAME", path);
	set_env(env, "SCRIPT_FILENAME", fullpath);
	set_env(env, "REDIRECT_STATUS", "200");
	set_env(env, "PATH", config.scriptpath);
	
	establish_connection(&connection);
	begin_request(&connection);
	send_env(&connection, &env);
	
	while (!request_ended) {
		fd_set set;

		FD_ZERO(&set);
		FD_SET(connection->socket, &set);
		if (content_length)
		  FD_SET(STDIN_FILENO, &set);
		/*
		if (...)
			FD_SET(data_file, &set);
		*/

		select(3, &set, NULL, NULL, 0);
		
		if (FD_ISSET(connection->socket, &set)) {	
			switch (handle_record(&connection)) {
				case FCGI_END_REQUEST:
					request_ended = 1;
					break;
			}
		}
		if (FD_ISSET(STDIN_FILENO, &set)) {
			ssize_t n = send_stream(&connection, content_length, STDIN_FILENO);
			if (n <= 0 || n > content_length) {
			}
			content_length -= n;
			if (!content_length) {
				send_stream(&connection, 0, STDIN_FILENO);
			}
		}
		/*
		if (... && FD_ISSET(data_file, &set)) {
			ssite_t n = send_stream(&connection, ..., data_file);
			if (...) {
				send_stream(&connection, 0, data_file
		*/
	}

	disconnect(&connection);
	free_env(&env);
}

int establish_connection(fcgi_connection* connection) {
	struct sockaddr* addr;
	struct sockaddr_un addr_un;
	struct sockaddr_in addr_in;
	struct addrinfo* info;
	socklen_t len;

	int port;

	switch (connection->type) {
		case FCGI_UNIX_SOCKET:
			addr_un.sun_len = 0; 
			addr_un.sun_family = AF_UNIX;
			strcpy(addr_un.sun_path, connection->unixsocket);
			addr = &addr_un;
			len = sizeof(unsigned char) + sizeof(sa_family_t)
			      + strlen(connection->unixsocket) + 1;
			connection->socket = socket(PF_LOCAL, SOCK_STREAM, 0);
			break;
		case FCGI_INET_SOCKET:
			if (0 != getaddrinfo(connection->host, connection->port, NULL, &info)) {
				return -1;
			}
			addr = info->ai_addr;
			len = info->ai_addrlen;
			connection->socket = socket(PF_INET,  SOCK_STREAM, 0);
			break;
	}

	if (-1 == connection->socket) {
		return -1;
	}

	if (-1 == connect(connection->socket, addr, len)) {
		return -1;
	}	
}

void disconnect(fcgi_connection* connection) {
	close(connection->socket);
	connection->socket = -1;
}

void begin_request(fcgi_connection* connection) {
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

	write(connection->socket, &record_header, sizeof(record_header));
	write(connection->socket, &begin_header, sizeof(begin_header));
}

void set_env(fcgi_env* env, char* name, char* value) {
	size_t name_len  = strlen(name);
	size_t value_len = strlen(value);
	int pair_type = 0;

	if (name_len > 127)
		pair_type |= FCGI_PAIR_LONG_NAME;
	if (value_len > 127)
		pair_type |= FCGI_PAIR_LONG_VALUE;
	
	if (env->env_size + 8 + name_len + value_len < env->buffer_size) {
		env->buffer_size += MAX(1024, 8 + name_len + value_len);
		env->buffer = (char*)realloc(env->buffer, env->buffer_size);
	}
	
	char* p = env->buffer + env->env_size;
	
	switch (pair_type) {
		case FCGI_PAIR_TYPE_11:
			memset(p, 0, sizeof(FCGI_PAIR_TYPE_11));
			((FCGI_PAIR_TYPE_11*)p)->name_length    =         name_len;
			((FCGI_PAIR_TYPE_11*)p)->value_length   =         value_len;
			p += sizeof(FCGI_PAIR_TYPE_11);
			break;
		case FCGI_PARI_TYPE_14:
			memset(p, 0, sizeof(FCGI_PAIR_TYPE_14));
			((FCGI_PAIR_TYPE_14*)p)->name_length    =         name_len;
			((FCGI_PAIR_TYPE_14*)p)->value_length_0 =         value_len        & 0xff;
			((FCGI_PAIR_TYPE_14*)p)->value_length_1 =        (value_len >>  8) & 0xff;
			((FCGI_PAIR_TYPE_14*)p)->value_length_2 =        (value_len >> 16) & 0xff;
			((FCGI_PAIR_TYPE_14*)p)->value_length_3 = 0x80 | (value_len >> 24) & 0x7f;
			p += sizeof(FCGI_PAIR_TYPE_14);
			break;
		case FCGI_PARI_TYPE_41:
			memset(p, 0, sizeof(FCGI_PAIR_TYPE_41));
			((FCGI_PAIR_TYPE_41*)p)->name_length_0  =         name_len         & 0xff;
			((FCGI_PAIR_TYPE_41*)p)->name_length_1  =        (name_len  >>  8) & 0xff;
			((FCGI_PAIR_TYPE_41*)p)->name_length_2  =        (name_len  >> 16) & 0xff;
			((FCGI_PAIR_TYPE_41*)p)->name_length_3  = 0x80 | (name_len  >> 24) & 0x7f;
			((FCGI_PAIR_TYPE_41*)p)->value_length   =         value_len;
			p += sizeof(FCGI_PAIR_TYPE_41);
			break;
		case FCGI_PARI_TYPE_44:
			memset(p, 0, sizeof(FCGI_PAIR_TYPE_44));
			((FCGI_PAIR_TYPE_44*)p)->name_length_0  =         name_len         & 0xff;
			((FCGI_PAIR_TYPE_44*)p)->name_length_1  =        (name_len  >>  8) & 0xff;
			((FCGI_PAIR_TYPE_44*)p)->name_length_2  =        (name_len  >> 16) & 0xff;
			((FCGI_PAIR_TYPE_44*)p)->name_length_3  = 0x80 | (name_len  >> 24) & 0x7f;
			((FCGI_PAIR_TYPE_44*)p)->value_length_0 =         value_len        & 0xff;
			((FCGI_PAIR_TYPE_44*)p)->value_length_1 =        (value_len >>  8) & 0xff;
			((FCGI_PAIR_TYPE_44*)p)->value_length_2 =        (value_len >> 16) & 0xff;
			((FCGI_PAIR_TYPE_44*)p)->value_length_3 = 0x80 | (value_len >> 24) & 0x7f;
			p += sizeof(FCGI_PAIR_TYPE_44);
			break;
	}

	memcpy(p, name,  name_len);
	p += name_len;
	memcpy(p, value, value_len);
	p += value_len;

	env->env_size = p - env->buffer;
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

void build_env(fcgi_env* env) {
	set_env(env, "FCGI_WEBSERVER_ADDRS", getenv());
	set_env(env, "SERVER_SOFTWARE", SERVER_IDENT);
	set_env(env, "GATEWAY_INTERFACE", "CGI/1.1");
	set_env(env, "HTTPD_ROOT", getenv("HTTPD_ROOT"));
	set_env(env, "SERVER_PORT", getenv("SERVER_PORT"));
	set_env(env, "REMOTE_HOST", getenv("REMOTE_HOST"));
	set_env(env, "REMOTE_ADDR", getenv("REMOTE_ADDR"));
	set_env(env, "SERVER_PROTOCOL", getenv("SERVER_PROTOCOL"));
	set_env(env, "USER_AGENT", getenv("USER_AGENT"));
	set_env(env, "HTTP_USER_AGENT", getenv("HTTP_USER_AGENT"));
	set_env(env, "USER_AGENT_SHORT", getenv("USER_AGENT_SHORT"));
	set_env(env, "HTTP_ACCEPT", getenv("HTTP_ACCEPT"));
	set_env(env, "HTTP_ACCEPT_LANGUAGE", getenv("HTTP_ACCEPT_LANGUAGE"));
	set_env(env, "HTTP_ACCEPT_ENCODING", getenv("HTTP_ACCEPT_ENCODING"));
	set_env(env, "CONTENT_LENGTH", getenv("CONTENT_LENGTH"));
	if (getenv("CONTENT_TYPE"))
		set_env(env, "CONTENT_TYPE", getenv("CONTENT_TYPE"));
	set_env(env, "HTTP_HOST", getenv("HTTP_HOST"));
	set_env(env, "SERVER_NAME", getenv("SERVER_NAME"));
	set_env(env, "REQUEST_METHOD", getenv("REQUEST_METHOD"));
	set_env(env, "USER", getenv("USER"));
	set_env(env, "HOME", getenv("HOME"));
	set_env(env, "ORIG_PATH_TRANSLATED", getenv("ORIG_PATH_TRANSLATED"));
	if (getenv("QUERY_STRING"))
		set_env(env, "QUERY_STRING", getenv("QUERY_STRING"));
	//set_env(env, "AUTH_TYPE",
	//set_env(env, "REMOTE_USER",
	//set_env(env, "REMOTE_IDENT",
}

int send_env(fcgi_connection* connection, fcgi_env* env) {
	FCGI_record record_header;

	memset(&record_header, 0, sizeof(record_header));

	record_header.version      = FCGI_VERSION_1;
	record_header.type         = FCGI_PARAMS;
	record_header.request_id_0 = 1;
	
	char *p = env->buffer;
	char *q = env->buffer + env->env_size;
	
	while (p != q) {
		ptrdiff_t n = MIN(FCGI_MAX_BUFFER, q-p);
		record_header.content_length_0 =  n       & 0xff;
		record_header.content_length_1 = (n >> 8) & 0xff;
		if (sizeof(record_header) != write(connection->socket, &record_header, sizeof(record_header))) {
			return -1;
		}
		if (n != write(connection->socket, p, n)) {
			return -1;
		}
		p += n;
	}

	record_header.content_length_0 = 0;
	record_header.content_length_1 = 0;
	if (sizeof(record_header) != write(connection->socket, &record_header, sizeof(record_header))) {
		return -1;
	}

	return 0;
}

int handle_record(fcgi_connection* connection) {
	FCGI_record record_header;
	ssite_t content_length = 0;
	char padding[255];

	if (sizeof(record_header) != read(connection->socket, &record_header, sizeof(record_header))) {
		return -1;	
	}

	content_length = record_header.content_length_1 << 8 + record_header.content_length_0;

	switch (record_header->type) {
		case FCGI_END_REQUEST:
			break;
		case FCGI_STDOUT:
			recv_stream(connection, content_length, STDOUT_FILENO);
			break;
		case FCGI_STDERR:
			recv_stream(connection, content_length, STDERR_FILENO);
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
		read(connection->socket, &padding, record_header.padding_length)) {
		return -1;
	}

	return record_header->type;
}

ssize_t send_stream(fcgi_connection* connection, ssize_t length, int fd) {
	FCGI_record record_header;
	char* buffer = NULL;
	char padding[7];
	ssize_t n;

	n = MIN(FCGI_MAX_BUFFER, length);

	buffer = (char*)malloc(n);

	if (NULL == buffer) {
		return -1;
	}
	
	n = secread(fd, buffer, FCGI_MAX_BUFFER);

	if (n <= 0) {
		return -1;
	}

	memset(&record_header, 0, sizeof(record_header));

	record_header.version          = FCGI_VERSION_1;
	record_header.type             = FCGI_STDIN;
	record_header.request_id_0     = 1;
	record_header.content_length_0 =  n       & 0xff;
	record_header.content_length_1 = (n >> 8) & 0xff;
	record_header.padding_length   = n & 0x07 ? (~n & 0x07) + 1 : 0;

	if (sizeof(record_header) !=
		write(connection->socket, &record_header, sizeof(record_header))) {
		return -1;
	}
	if (n != write(connection->socket, buffer, n)) {
		return -1;
	}
	if (record_header.padding_length !=
		write(connection->socket, &padding, record_header.padding_length)) {
		return -1;
	}

	return n;
}

ssize_t recv_stream(fcgi_connection* connection, ssize_t length, int fd) {
	char* buffer = NULL;
	ssize_t n = length;

	if (length == 0)
		return 0;

	buffer = (char*)malloc(n);

	n = read(connection->socket, buffer, n);

	if (n <= 0) {
		return -1;
	}

	if (n != secwrite(fd, &buffer, n)) {
		return -1;
	}

	return n;
}
