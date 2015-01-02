/* Copyright (C) 2009-2015 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdlib.h>
#include	<err.h>

#define		PERL_NO_SHORT_NAMES
#include	<EXTERN.h>
#include	<perl.h>

#include	"malloc.h"
#include	"modules.h"
#include	"path.h"

char		*perlargs[] = { NULL, NULL };
char		*perlscript = NULL;
PerlInterpreter	*my_perl = NULL;

bool	perl_init(void);
bool	perl_handler(const char *filename, int fdin, int fdout);
bool	perl_config_general(const char *key, const char *value);

bool
perl_init(void)
{
	char	*path, *embedding[] = { NULL, NULL };
	int	exitstatus = 0;

	if (!(my_perl = perl_alloc()))
		err(1, "No memory!");
	perl_construct(my_perl);

	/* perl_parse() doesn't like const arguments: pass dynamic */
	if (perlscript)
		STRDUP(path, calcpath(CONTRIB_DIR, perlscript));
	else
		STRDUP(path, calcpath(CONTRIB_DIR, "persistent.pl"));
	if (!access(path, R_OK))
	{
		embedding[0] = embedding[1] = path;
		exitstatus = perl_parse(my_perl, NULL, 2, embedding, NULL);
		if (!exitstatus)
		{
			perl_run(my_perl);
			FREE(path);
			return true;
		}
	}

	warn("Perl module not available");
	FREE(path);
	perl_free(my_perl);
	my_perl = NULL;
	return false;
}

bool
perl_handler(const char *filename, int fdin, int fdout)
{
	/* XXX: Should use fdin rather than filename */

	dup2(fdout, STDOUT_FILENO);
	STRDUP(perlargs[0], filename);
	Perl_call_argv(aTHX_ "Embed::Persistent::eval_file",
		G_DISCARD | G_EVAL, perlargs);
	(void)fdin;
	return true;
}

bool
perl_config_general(const char *key, const char *value)
{
	if (key && !strcasecmp("PerlPersistentScript", key))
	{
		STRDUP(perlscript, value);
		return true;
	}
	return false;
}

struct module perl_module =
{
	.name = "perl interpreter",
	.engine = "internal:perl",
	.init = perl_init,
	.file_handler = perl_handler,
	.config_general = perl_config_general,
};

