/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
#ifndef		HAVE_STRCASESTR
extern	const	char	*strcasestr		PROTO((const char *, const char *));
#endif		/* HAVE_STRCASESTR */
extern	int	mysleep			PROTO((int));
#ifndef		HAVE_KILLPG
extern	int	killpg			PROTO((pid_t, int));
#endif		/* HAVE_KILLPG */
extern	int	match			PROTO((const char *, const char *));
extern	int	match_list		PROTO((char *, const char *));
#ifndef		HAVE_STRERROR
extern	const	char	*strerror	PROTO((int));
#endif		/* HAVE_STRERROR */
#endif		/* NOFORWARDS */
