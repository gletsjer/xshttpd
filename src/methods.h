/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
extern	VOID	senduncompressed	PROTO((int));
#ifdef		HANDLE_COMPRESSED
extern	VOID	sendcompressed		PROTO((int, const char *));
extern	VOID	loadcompresstypes	PROTO((void));
#endif		/* HANDLE_COMPRESSED */
extern	VOID	loadfiletypes		PROTO((void));
extern	int	getfiletype		PROTO((int));

extern	VOID	do_get			PROTO((char *));
extern	VOID	do_post			PROTO((char *));
extern	VOID	do_head			PROTO((char *));
extern	VOID	do_options		PROTO((char *));
#endif		/* NOFORWARDS */
