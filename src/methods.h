/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
extern	void	loadcompresstypes	(void);
extern	void	loadscripttypes		(char *, char *);
#ifdef		HANDLE_SSL
extern	void	loadssl				(void);
#endif		/* HANDLE_SSL */
extern	void	loadfiletypes		(char *, char *);
#ifdef		HANDLE_PERL
extern	void	loadperl			(void);
#endif		/* HANDLE_PERL */

extern	void	do_get			(char *);
extern	void	do_post			(char *);
extern	void	do_head			(char *);
extern	void	do_options		(const char *);
#endif		/* NOFORWARDS */

