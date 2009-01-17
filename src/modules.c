/* Copyright (C) 2009 by Johan van Selst */

#include	"config.h"

#include	<stdlib.h>
#include	<string.h>
#include	<dlfcn.h>

#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

const char	*module_names[] = MODULES;
struct module	**modules = NULL;

bool
init_modules(void)
{
	size_t	num_mod;
	void	*handle;
	char	*modname, *soname;
	struct module	*module;
	const char	*module_dir = calcpath(MODULE_DIR);

	for (num_mod = 0; module_names[num_mod]; num_mod++)
		/* DO NOTHING */;

	MALLOC(modules, struct module *, num_mod + 1);
	for (size_t i = 0; i < num_mod; i++)
	{
		asprintf(&soname, "%s/mod_%s.so", module_dir, module_names[i]);
		asprintf(&modname, "%s_module", module_names[i]);
		handle = dlopen(soname, RTLD_LAZY);
		if (!handle)
			errx(1, "Cannot load module %s: %s",
				module_names[i], dlerror());
		module = (struct module *)dlsym(handle, modname);
		if (!module)
			errx(1, "Cannot load module %s: %s",
				module_names[i], dlerror());
		warnx("Module loaded: %s", module->name);
		free(modname);
		free(soname);
		modules[i] = module;
	}
	modules[num_mod] = NULL;

	return true;
}
