/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		NOFORWARDS
#ifndef		HAVE_STRCASESTR
extern	const	char	*strcasestr		(const char *, const char *);
#endif		/* HAVE_STRCASESTR */
extern	int	mysleep			(int);
#ifndef		HAVE_KILLPG
extern	int	killpg			(pid_t, int);
#endif		/* HAVE_KILLPG */
extern	int	match			(const char *, const char *);
extern	int	match_list		(char *, const char *);
#ifndef		HAVE_STRERROR
extern	const	char	*strerror	(int);
#endif		/* HAVE_STRERROR */
#endif		/* NOFORWARDS */
