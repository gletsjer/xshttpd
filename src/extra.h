/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		HAVE_STRCASESTR
const	char	*strcasestr		(const char *, const char *);
#endif		/* HAVE_STRCASESTR */
int	mysleep			(int);
#ifndef		HAVE_KILLPG
int	killpg			(pid_t, int);
#endif		/* HAVE_KILLPG */
int	match			(const char *, const char *);
int	match_list		(char *, const char *);
#ifndef		HAVE_STRERROR
const	char	*strerror	(int);
#endif		/* HAVE_STRERROR */
