/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* This file contains the backup definitions for old systems. */

#ifndef		HAVE_VFORK
#define		vfork		fork
#endif		/* HAVE_VFORK */

#ifdef		NOCONST
#define		const
#endif		/* NOCONST */

#ifdef		NOSTATIC
#define		static
#endif		/* NOSTATIC */

#ifdef		NOEXTERN
#define		extern
#endif		/* NOEXTERN */

#ifdef		NOvoid
#define		void
#else		/* Not NOvoid */
#define		void		void
#endif		/* NOvoid */

#ifdef		NOPID_T
#define		pid_t		long
#endif		/* NOPID_T */

#ifdef		NOSIZE_T
#define		size_t		long
#endif		/* NOSIZE_T */

#ifdef		NOUID_T
#define		pid_t		int
#endif		/* NOUID_T */

#ifdef		NOGID_T
#define		gid_t		int
#endif		/* NOGID_T */

#ifndef		HAVE_BCOPY
#define		bcopy(a,b,c)	memmove((b), (a), (c))
#endif		/* HAVE_MEMMOVE */

#ifndef		HAVE_BZERO
#define		bzero(a,b)	memset((a), 0, (b))
#endif		/* HAVE_BZERO */

#ifndef		HAVE_SETEUID
#ifdef		HAVE_SETRESUID
#define		seteuid(a)	setresuid(-1, (a), -1)
#else		/* Not HAVE_SETRESUID */
#define		seteuid(a)	setreuid(-1, (a))
#endif		/* HAVE_SETRESUID */
#endif		/* HAVE_SETEUID */

#ifndef		HAVE_SETEGID
#ifdef		HAVE_SETRESGID
#define		setegid(a)	setresgid(-1, (a), -1)
#else		/* Not HAVE_SETRESGID */
#define		setegid(a)	setregid(-1, (a))
#endif		/* HAVE_SETRESGID */
#endif		/* HAVE_SETEGID */

#ifdef		__GNUC__
#define		PRINTF_LIKE(f, p)	__attribute__ ((format (printf, f, p)))
#define		CONST_FUNC		__attribute__ ((const))
#define		NORETURN		__attribute__ ((noreturn))
#else
#define		PRINTF_LIKE(f, p)
#define		CONST_FUNC
#define		NORETURN
#endif		/* __GNUC__ */
