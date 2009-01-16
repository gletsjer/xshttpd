/* Copyright (C) 2009 by Johan van Selst */

#include	"config.h"

#include	<stdlib.h>
#include	<string.h>
#include	<dlfcn.h>

#include	"malloc.h"

const char	*module_names[] = MODULES;

struct module **modules = NULL;

bool
init_modules(void)
{
	size_t	num_mod;
	void	*handle;
	char	*modname, *soname;
	struct module	*module;

	for (num_mod = 0; module_names[num_mod]; num_mod++)
		/* DO NOTHING */;

	MALLOC(modules, struct module *, num_mod + 1);
	for (size_t i = 0; i < num_mod; i++)
	{
		asprintf(&soname, "mod_%s.so", module_names[i]);
		asprintf(&modname, "_%s_module_p", module_names[i]);
		handle = dlopen(soname, RTLD_NOW);
		modules[i] = (struct module *)dlsym(handle, modname);
		free(modname);
		free(soname);
	}
	modules[num_mod] = NULL;

	return true;
}
