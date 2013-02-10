/* Copyright (C) 2009-2013 by Johan van Selst (johans@stack.nl) */

#include	"config.h"
#include	"modules.h"

#include	<php/sapi/embed/php_embed.h>

#include	<stdlib.h>
#include	<err.h>

#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

char		*phpargs[] = { NULL, NULL };
char		*phpscript = NULL;

int	php_fdout;

bool	php_init(void);
bool	php_handler(const char *filename, int fdin, int fdout);
bool	php_config_general(const char *key, const char *value);

static int
php_ubwrite(const char *str, unsigned int str_length TSRMLS_DC)
{
	return write(php_fdout, str, (size_t)str_length);
}

bool
php_init(void)
{
	static char	*argv[2] = { "myname", NULL };
	int		ret;

	ret = php_embed_init(1, argv PTSRMLS_CC);
	
	if (ret != FAILURE)
		return true;

	php_embed_module.ub_write = php_ubwrite;

	warn("PHP module not available");
	return false;
}

bool
php_handler(const char *filename, int fdin, int fdout)
{
	zend_file_handle	file_handle;
	int			exit_status;
	/* XXX: Should use fdin rather than filename */

	file_handle.filename = "-";
	file_handle.type = ZEND_HANDLE_FP;
	file_handle.handle.fp = fdopen(fdin, "rb");
	file_handle.opened_path = NULL;
	file_handle.free_filename = 0;

	php_fdout = fdout;

	php_execute_script(&file_handle TSRMLS_CC);
	exit_status = EG(exit_status);

	zend_file_handle_dtor(&file_handle TSRMLS_CC);
	return true;
}

bool
php_config_general(const char *key, const char *value)
{
	if (key && !strcasecmp("PHPEmbedScript", key))
		return true;
	return false;
}

struct module php_module =
{
	.name = "php interpreter",
	.engine = "internal:php",
	.init = php_init,
	.file_handler = php_handler,
	.config_general = php_config_general,
};

