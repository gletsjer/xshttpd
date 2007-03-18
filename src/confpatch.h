/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* This file contains the backup definitions for old systems. */

#ifdef		NOCONST
#define		const
#endif		/* NOCONST */

#ifdef		NOSTATIC
#define		static
#endif		/* NOSTATIC */

#ifdef		NOEXTERN
#define		extern
#endif		/* NOEXTERN */

#ifdef		NOVOID
#define		void
#else		/* Not NOVOID */
#define		void		void
#endif		/* NOVOID */

#ifdef		NOPID_T
#define		pid_t		long
#endif		/* NOPID_T */

#ifdef		NOSIZE_T
#define		size_t		long
#endif		/* NOSIZE_T */

#ifdef		NOUID_T
#define		uid_t		int
#endif		/* NOUID_T */

#ifdef		NOGID_T
#define		gid_t		int
#endif		/* NOGID_T */

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
