/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

void	loadcompresstypes	(void);
void	loadscripttypes		(char *, char *);
#ifdef		HANDLE_SSL
void	loadssl				(void);
#endif		/* HANDLE_SSL */
void	loadfiletypes		(char *, char *);
#ifdef		HANDLE_PERL
void	loadperl			(void);
#endif		/* HANDLE_PERL */

void	do_get			(char *);
void	do_post			(char *);
void	do_head			(char *);
void	do_options		(const char *);

