/* Copyright (C) 2009 Johan van Selst */

#ifndef		MODULES_H
#define		MODULES_H

#include	<stdbool.h>

#include	"httypes.h"
#include	"config.h"

extern const char	*module_names[];

bool	init_modules(void);

struct encoding_filter
{
	void *	(*open)		(int fd);
	int	(*read)		(void *fdp, char *buf, size_t len);
	int	(*close)	(void *fdp);
	off_t	(*seek)		(void *fdp, off_t offset, int whence);
	off_t	(*size)		(int fd);
};

typedef ssize_t (*readline_callback_t)(char *, size_t);
typedef ssize_t (*read_callback_t)(char *, size_t);
typedef ssize_t (*write_callback_t)(const char *, size_t);

struct module
{
	const char	*name;
	const char	*engine;
	const char	*file_extension;
	const char	*file_encoding;
	bool	(*init) (void);
	bool	(*file_handler)	(const char *filename, int fdin, int fdout);
	bool	(*http_request)	(const char *filename, const char *headers);
	bool	(*http_headers)	(const char *filename, char **headers);
	bool	(*protocol_handler)	(struct maplist *query_headers,
			read_callback_t rcb, write_callback_t);
	struct encoding_filter	*inflate_filter;
	struct encoding_filter	*deflate_filter;
	bool	(*auth_basic)	(const char *username, const char *password);
	bool	(*auth_digest)	(const char *username, const char *password);
	bool	(*config_general) (const char *key, const char *value);
	bool	(*config_local)	(const char *key, const char *value);
};

extern struct module **modules;

#endif		/* MODULES_H */
