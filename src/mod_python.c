/* Copyright (C) 2009-2013 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<err.h>

#include	<Python.h>

#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

bool	python_init(void);
bool	python_handler(const char *filename, int fdin, int fdout);

bool
python_init()
{
	Py_InitializeEx(0);
	return true;
}

bool
python_handler(const char *filename, int fdin, int fdout)
{
	FILE    *fp = fdopen(fdin, "r");

	dup2(fdout, STDOUT_FILENO);
	PyRun_SimpleFile(fp, filename);
	fclose(fp);
	return true;
}

struct module python_module =
{
	.name = "python interpreter",
	.engine = "internal:python",
	.init = python_init,
	.file_handler = python_handler,
};

