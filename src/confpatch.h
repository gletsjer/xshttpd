/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
 
/* This file contains the backup definitions for old systems. */

#ifndef		HAVE_VFORK
#define		vfork		fork
#endif		/* HAVE_VFORK */

#ifndef		NOPROTOS
#define		PROTO(a)	a
#else
#define		PROTO(a)	()
#endif

#ifndef		NONEWSTYLE
#define		DECL0			(void)
#define		DECL1(t1,v1)		(t1 v1)
#define		DECL2(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL3(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#define		DECL4(t1,v1,t2,v2,t3,v3,t4,v4) (t1 v1, t2 v2, t3 v3, t4 v4)
#define		DECL5(t1,v1,t2,v2,t3,v3,t4,v4,t5,v5) (t1 v1, t2 v2, t3 v3, t4 v4, t5 v5)
#ifdef		NOCONST
#define		DECL1C(t1,v1)		(t1 v1)
#define		DECL2C_(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL2_C(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL2CC(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#else		/* Not NOCONST */
#define		DECL1C(t1,v1)		(const t1 v1)
#define		DECL2C_(t1,v1,t2,v2)	(const t1 v1, t2 v2)
#define		DECL2_C(t1,v1,t2,v2)	(t1 v1, const t2 v2)
#define		DECL2CC(t1,v1,t2,v2)	(const t1 v1, const t2 v2)
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (t1 v1, const t2 v2, t3 v3)
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (const t1 v1, const t2 v2, t3 v3)
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (const t1 v1, t2 v2, t3 v3)
#endif		/* NOCONST */
#else		/* Not not NONEWSTYLE */
#define		DECL0			()
#define		DECL1(t1,v1)		(v1) t1 v1;
#define		DECL2(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL3(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#define		DECL4(t1,v1,t2,v2,t3,v3,t4,v4) \
				(v1, v2, v3, v4) t1 v1; t2 v2; t3 v3; t4 v4;
#ifdef		NOCONST
#define		DECL1C(t1,v1)		(v1) t1 v1;
#define		DECL2C_(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL2CC(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL2_C(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#else		/* Not NOCONST */
#define		DECL1C(t1,v1)		(v1) const t1 v1;
#define		DECL2C_(t1,v1,t2,v2)	(v1, v2) const t1 v1; t2 v2;
#define		DECL2CC(t1,v1,t2,v2)	(v1, v2) const t1 v1; const t2 v2;
#define		DECL2_C(t1,v1,t2,v2)	(v1, v2) t1 v1; const t2 v2;
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; const t2 v2; t3 v3;
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) const t1 v1; const t2 v2; t3 v3;
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (v1, v2, v3) const t1 v1; t2 v2; t3 v3;
#endif		/* NOCONST */
#endif		/* NONEWSTYLE */

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
#define		VOID
#else		/* Not NOVOID */
#define		VOID		void
#endif		/* NOVOID */

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
