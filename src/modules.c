/* Copyright (C) 2009-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<string.h>
#include	<dlfcn.h>

#include	"htconfig.h"
#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

const char * const	module_names[] = MODULES;
struct module		**modules = NULL;

bool
init_modules(void)
{
	size_t		num_mod;
	void		*handle;
	char		*modname, *soname;
	struct module	*module;
	const char	module_dir[] = MODULE_DIR;

	if (!config.modules ||
			(config.modules[0] && '*' == config.modules[0][0]))
	{
		MALLOC(config.modules, char *, sizeof(module_names));
		memcpy(config.modules, module_names, sizeof(module_names));
	}

	for (num_mod = 0; config.modules[num_mod]; num_mod++)
		/* DO NOTHING */;

	MALLOC(modules, struct module *, num_mod + 1);
	for (size_t i = 0; i < num_mod; i++)
	{
		ASPRINTF(&soname, "%s/mod_%s.so", module_dir,config.modules[i]);
		ASPRINTF(&modname, "%s_module", config.modules[i]);
		handle = dlopen(soname, RTLD_LAZY);
		if (!handle)
			errx(1, "Cannot load module %s: %s",
				config.modules[i], dlerror());
		module = (struct module *)dlsym(handle, modname);
		if (!module)
			errx(1, "Cannot load module %s: %s",
				config.modules[i], dlerror());
		warnx("Module loaded: %s", module->name);
		FREE(modname);
		FREE(soname);
		modules[i] = module;
	}
	modules[num_mod] = NULL;

	return true;
}
