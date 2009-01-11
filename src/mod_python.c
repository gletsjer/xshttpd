/* Copyright (C) 2009 Johan van Selst */

#include	"config.h"

#include	<stdlib.h>
#include	<err.h>

#include	<python2.5/Python.h>

#include	"htconfig.h"
#include	"malloc.h"
#include	"modules.h"
#include	"path.h"


int
python_init()
{
	Py_InitializeEx(0);
	return 0;
}

int
python_handler(char *filename)
{
	FILE    *fp = fopen(filename, "r");
	PyRun_SimpleFile(fp, filename);
	fclose(fp);
	return 0;
}

struct module python_module =
{
	.name = "python interpreter",
	.engine = "internal:python",
	.init = python_init,
	.file_handler = python_handler,
};

