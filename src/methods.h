/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
extern	VOID	loadcompresstypes	PROTO((void));
extern	VOID	loadscripttypes		PROTO((char *, char *));
#ifdef		HANDLE_SSL
extern	VOID	loadssl				PROTO((void));
#endif		/* HANDLE_SSL */
extern	VOID	loadfiletypes		PROTO((char *, char *));
#ifdef		HANDLE_PERL
extern	VOID	loadperl			PROTO((void));
#endif		/* HANDLE_PERL */

extern	VOID	do_get			PROTO((char *));
extern	VOID	do_post			PROTO((char *));
extern	VOID	do_head			PROTO((char *));
extern	VOID	do_options		PROTO((const char *));
#endif		/* NOFORWARDS */

