/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

void	loadcompresstypes	(void);
void	loadscripttypes		(char *, char *);
void	loadfiletypes		(char *, char *);
#ifdef		HAVE_PERL
void	loadperl			(void);
#endif		/* HAVE_PERL */
#ifdef		HAVE_PYTHON
void	loadpython			(void);
#endif		/* HAVE_PYTHON */

void	do_get			(char *);
void	do_post			(char *);
void	do_head			(char *);
void	do_options		(const char *);
void	do_proxy		(const char *, const char *);

