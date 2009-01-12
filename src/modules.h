/* Copyright (C) 2009 Johan van Selst */

#ifndef		MODULES_H
#define		MODULES_H

#include	"config.h"

struct module
{
	char	*name;
	char	*engine;
	int	(*init) (void);
	int	(*file_handler) (char *);
};

extern struct module *modules[];

#endif		/* MODULES_H */