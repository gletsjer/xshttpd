/* Copyright (C) 2009 Johan van Selst */

#ifndef		MODULES_H
#define		MODULES_H

#include	<stdbool.h>

#include	"config.h"

extern const char	*module_names[];

bool	init_modules(void);

struct module
{
	const char	*name;
	const char	*engine;
	const char	*file_extension;
	const char	*file_encoding;
	bool	(*init) (void);
	bool	(*file_handler) (const char *filename, int fdin, int fdout);
	bool	(*inflate_handler) (const char *filename, int fdin, int fdout);
	bool	(*deflate_handler) (const char *filename, int fdin, int fdout);
	bool	(*auth_basic) (const char *username, const char *password);
	bool	(*auth_digest) (const char *username, const char *password);
	bool	(*config_general) (const char *key, const char *value);
	bool	(*config_local) (const char *key, const char *value);
};

extern struct module **modules;

#endif		/* MODULES_H */
