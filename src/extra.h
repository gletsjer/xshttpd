/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		EXTRA_H
#define		EXTRA_H

#include	<stdbool.h>
#include	"httypes.h"

struct tm *	localtimenow	(void) WARNUNUSED;
char *	gmtimestamp		(void) WARNUNUSED;
bool	mysleep			(int);
bool	match			(const char * const, const char * const) NONNULL WARNUNUSED;
bool	match_list		(const char * const, const char * const) NONNULL WARNUNUSED;
bool	fnmatch_array		(char * const * const array, const char * const pattern, int flags) NONNULL WARNUNUSED;
size_t	string_to_array		(const char * const, char **) NONNULL1;	/* prealloced */
size_t	string_to_arrayp	(const char * const, char ***) NONNULL1;	/* malloc()s */
size_t	string_to_arraypn	(const char * const, char ***) NONNULL1;	/* malloc() + 0-terminates */
size_t	qstring_to_array	(const char * const, char **) NONNULL1;	/* ;q-value strings */
size_t	qstring_to_arrayp	(const char * const, char ***) NONNULL1;
size_t	qstring_to_arraypn	(const char * const, char ***) NONNULL1;
size_t	eqstring_to_array	(const char * const, struct maplist **) NONNULL1;	/* idx=val strings */
void	free_string_array	(char **, size_t);
void	free_string_arrayp	(char **);
ssize_t	fgetfields		(FILE *, size_t, ...);
ssize_t	fgetmfields		(FILE *, char ***);
int	get_temp_fd		(void);
int	maplist_append		(struct maplist *, xs_appendflags_t, const char *, const char *, ...) PRINTF_LIKE(4, 5);
void	maplist_free		(struct maplist *);
char	*do_crypt		(const char * const key, const char * const iv);

#endif		/* EXTRA_H */
