/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* This file contains the backup definitions for old systems. */
/* autoconfs handles keywords like const and types as uid_t for us. */

#ifndef		COMPILER_H
#define		COMPILER_H

#ifdef		__GNUC__
# if		__GNUC__ >= 3
#  define	PRINTF_LIKE(f, p)	__attribute__ ((format (printf, (f), (p))))\
					__attribute__ ((__nonnull__ (f)))
#  define	CONST_FUNC		__attribute__ ((const))
#  define	MALLOC_FUNC		__attribute__ ((malloc)) \
 					__attribute__ ((warn_unused_result))
#  define	NORETURN		__attribute__ ((noreturn))
#  define	NONNULL			__attribute__ ((nonnull))
#  define	NONNULL1		__attribute__ ((nonnull (1)))
#  define	WARNUNUSED		__attribute__ ((warn_unused_result))
# else		/* __GNUC__ < 3 */
#  define	PRINTF_LIKE(f, p)	__attribute__ ((format (printf, (f), (p))))
#  define	CONST_FUNC		__attribute__ ((const))
#  define	MALLOC_FUNC
#  define	NORETURN
#  define	NONNULL
#  define	NONNULL1
#  define	WARNUNUSED
# endif		/* __GNUC__ < 3 */
#else		/* Not __GNUC__ */
# define	PRINTF_LIKE(f, p)
# define	CONST_FUNC
# define	MALLOC_FUNC
# define	NORETURN
# define	NONNULL
# define	NONNULL1
# define	WARNUNUSED
#endif		/* __GNUC__ */

#endif		/* COMPILER_H */
