#ifndef		CLOADER_H
#define		CLOADER_H

#include	"config.h"

extern char	config_path[XS_PATH_MAX], config_preprocessor[XS_PATH_MAX];

void	load_config	(void);
void	remove_config	(void);
#ifdef		HAVE_PERL
void	loadperl	(void);
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
void	loadpython	(void);
#endif		/* HAVE_PYTHON */

#endif		/* CLOADER_H */
