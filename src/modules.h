/* Copyright (C) 2009 Johan van Selst */

#ifndef		MODULES_H
#define		MODULES_H

#include	"config.h"

extern const char	*module_names[];

bool	init_modules(void);

struct module
{
	const char	*name;
	const char	*engine;
	int	(*init) (void);
	int	(*file_handler) (const char *filename);
	bool	(*auth_basic) (const char *username, const char *password);
	bool	(*auth_digest) (const char *username, const char *password);
	bool	(*config_general) (const char *key, const char *value);
	bool	(*config_local) (const char *key, const char *value);
};

extern struct module **modules;

#endif		/* MODULES_H */
