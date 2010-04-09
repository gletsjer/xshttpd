/* Copyright (C) 2009-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<unistd.h>
#include	<err.h>

#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

extern void     ruby_run(void);
extern void     rb_load_file(const char *);
extern void	ruby_init(void);
extern void	ruby_init_loadpath(void);
extern void	ruby_script(const char *);

bool		mod_ruby_init(void);
bool		ruby_handler(const char *filename, int fdin, int fdout);

bool
mod_ruby_init(void)
{
	ruby_init();
	ruby_init_loadpath();
	ruby_script("embedded");
	return true;
}

bool
ruby_handler(const char *filename, int fdin, int fdout)
{
	dup2(fdout, STDOUT_FILENO);
	rb_load_file(filename);
	ruby_run();
	(void)fdin;
	return true;
}

struct module ruby_module =
{
	.name = "ruby interpreter",
	.engine = "internal:ruby",
	.init = mod_ruby_init,
	.file_handler = ruby_handler,
};
