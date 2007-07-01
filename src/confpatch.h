/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* This file contains the backup definitions for old systems. */
/* autoconfs handles keywords like const and types as uid_t for us. */

#ifndef		CONFPATCH_H
#define		CONFPATCH_H

#ifdef		__GNUC__
# if		__GNUC__ >= 3
#  define	PRINTF_LIKE(f, p)	__attribute__ ((format (printf, (f), (p))))\
					__attribute__ ((__nonnull__ (f)))
#  define	CONST_FUNC		__attribute__ ((const))
#  define	MALLOC_FUNC		__attribute__ ((malloc))
#  define	NORETURN		__attribute__ ((noreturn))
# else		/* __GNUC__ < 3 */
#  define	PRINTF_LIKE(f, p)	__attribute__ ((format (printf, (f), (p))))
#  define	CONST_FUNC		__attribute__ ((const))
#  define	MALLOC_FUNC
#  define	NORETURN
# endif		/* __GNUC__ < 3 */
#else		/* Not __GNUC__ */
# define	PRINTF_LIKE(f, p)
# define	CONST_FUNC
# define	MALLOC_FUNC
# define	NORETURN
#endif		/* __GNUC__ */

#endif		/* CONFPATCH_H */
