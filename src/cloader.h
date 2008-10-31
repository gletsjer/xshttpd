#ifndef		CLOADER_H
#define		CLOADER_H

#include	"config.h"

extern char	*config_path, *config_preprocessor;

void	load_config	(void);
void	remove_config	(void);
#ifdef		HAVE_PERL
void	loadperl	(void);
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
void	loadpython	(void);
#endif		/* HAVE_PYTHON */
#ifdef		HAVE_RUBY
void	loadruby	(void);
#endif		/* HAVE_RUBY */

#endif		/* CLOADER_H */
