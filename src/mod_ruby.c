/* Copyright (C) 2009 Johan van Selst */

#include	"config.h"

#include	<stdlib.h>
#include	<err.h>

#include	"htconfig.h"
#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

extern void     ruby_run(void);
extern void     rb_load_file(const char *);
extern void	ruby_init(void);
extern void	ruby_script(const char *);

int
mod_ruby_init(void)
{
	ruby_init();
	ruby_script("embedded");
	return 0;
}

int
ruby_handler(char *filename)
{
	rb_load_file(filename);
	ruby_run();
	return 0;
}

struct module ruby_module =
{
	.name = "ruby interpreter",
	.engine = "internal:ruby",
	.init = mod_ruby_init,
	.file_handler = ruby_handler,
};
