/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
extern	VOID	senduncompressed	PROTO((int));
#ifdef		HANDLE_COMPRESSED
extern	VOID	sendcompressed		PROTO((int, const char *));
extern	VOID	loadcompresstypes	PROTO((void));
#endif		/* HANDLE_COMPRESSED */
#ifdef		HANDLE_SCRIPT
extern	VOID	loadscripttypes		PROTO((void));
#endif		/* HANDLE_SCRIPT */
#ifdef		HANDLE_SSL
extern	VOID	loadssl				PROTO((void));
#endif		/* HANDLE_SSL */
extern	VOID	loadfiletypes		PROTO((void));
extern	int	getfiletype		PROTO((int));
extern	int	allowxs			PROTO((char *));

extern	VOID	do_get			PROTO((char *));
extern	VOID	do_post			PROTO((char *));
extern	VOID	do_head			PROTO((char *));
extern	VOID	do_options		PROTO((char *));
#endif		/* NOFORWARDS */
