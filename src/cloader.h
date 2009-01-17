#ifndef		CLOADER_H
#define		CLOADER_H

#include	"config.h"

extern char	*config_path, *config_preprocessor;

void	load_config	(void);
void	module_config	(void);
void	remove_config	(void);

#endif		/* CLOADER_H */
