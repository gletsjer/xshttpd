dnl Make my life easier
# XS_ARG_DEFAULT(option, define, def.value, help string)
AC_DEFUN([XS_ARG_DEFAULT], [
	AC_MSG_CHECKING(for --enable-$1)
	AC_ARG_ENABLE($1,
		AC_HELP_STRING([--enable-$1], [$4 ($3)]),
		AC_MSG_RESULT(${enable_$1}),
		AS_TR_SH(enable_$1)=$3
		AC_MSG_RESULT($3))
	AS_IF([test "${enable_$1}" = yes], AC_DEFINE($2,, [$4]))
	])

dnl AC_DEFUN([ac_ARG_DIR], [
dnl 	AC_ARG_WITH($1,
dnl 		[  --with-$1=PATH	  directory to use for $2 [ROOTDIR/$2]],
dnl 		$1=${withval},
dnl 		$1=${rootdir}/$2)
dnl 	])
AC_DEFUN([XS_ARG_DIRS], [
	m4_foreach_w([loc], [$1], [
		CFLAGS="${CFLAGS} -[D]AS_TR_CPP(loc[_DIR])=\\\"${loc[dir]}\\\""
		AC_DEFINE(AS_TR_CPP(loc[_DIRT]), [AS_TR_CPP(loc[_DIR]) "/"],
			[loc directory with opt. trailing slash])
		AS_IF([test "${loc[dir]}" = "${loc[dir]#[/\$]}"],
			AC_MSG_ERROR([Config directory loc[dir] must refer to an absolute path])
			AC_SUBST(loc[dir]))
		])
	])

# AC_FUNC_IN_LIB(function, define, library, buildprog, extra-lib,
	[action-if-found], [action-if-not-found])
AC_DEFUN([XS_FUNC_IN_LIB], [
	LIBS=
	AH_TEMPLATE($2, [Define to 1 if you have the `$1' function])
	AC_SEARCH_LIBS($1, $3, [AC_DEFINE($2)],, $5)
	AS_IF([test -n "${LIBS}"], [
		$4_ldflags="${$4_ldflags} ${LIBS} $5"
		])
	AS_IF([test "x${ac_cv_search_$1}" != x -a "x${ac_cv_search_$1}" != xno],
		[$6], [$7])
	LIBS=
	])

# XS_CHECK_WITH(function, desc, default, [action-if-yes], [action-if-no])
AC_DEFUN([XS_CHECK_WITH], [
	AC_MSG_CHECKING([if you want $2])
	AC_ARG_WITH($1,
		AC_HELP_STRING([--with-$1], [$2 ($3)]),
		AC_MSG_RESULT(${with_$1}),
		AS_TR_SH(with_$1)=$3
		AC_MSG_RESULT($3))
	AS_IF([test x$with_$1 != x -a x$with_$1 != xno], [$4], [$5])
	])

AC_DEFUN([XS_FATAL], [
	AC_MSG_ERROR([Cannot find $1 support, rerun with --without-$1])
	])

# XS_CHECK_PC(prog, library, [action-if-yes], [action-if-no])
AC_DEFUN([XS_CHECK_PC], [
	PKG_CHECK_MODULES(AS_TR_SH($1), [lib$1], [
		$2_cflags="${$2_cflags} ${AS_TR_SH($1_CFLAGS)}"
		$2_ldflags="${$2_ldflags} ${AS_TR_SH($1_LIBS)}"
		AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_$1), 1,
			[Define this if you have the $1 libary])
		$3
		],
		[$4])
	])

# XS_TRY_CONFIG(path, buildprog, [action-if-found], [action-if-not-found])
AC_DEFUN([XS_TRY_CONFIG], [
	    AC_PATH_PROG(AS_TR_SH(xs_$1_path), $1-config)
	    AS_IF([test -n "${AS_TR_SH(xs_$1_path)}"], [
		$2_cflags="${$2_cflags} `${AS_TR_SH(xs_$1_path)} --cflags`"
		$2_ldflags="${$2_ldflags} `${AS_TR_SH(xs_$1_path)} --libs`"
		AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_$1), 1,
			[Define this if you have the $1 libary])
		$3
		], [
		$4
		AC_MSG_ERROR([Cannot find $1 support, rerun with --without-$1])
		])
	])

AC_DEFUN([XS_FUNC_SENDFILE], [
	AC_MSG_CHECKING([for sendfile])
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>
#ifdef	HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif
#include <sys/socket.h>
#include <sys/uio.h>],
		[sendfile(0, 0, 0, 0, (void *)0, (void *)0, 0);]),
		[AC_MSG_RESULT([yes])
		 AC_DEFINE(HAVE_BSD_SENDFILE, [],
			 [Define to 1 if you have the BSD-style 'sendfile' function])
		 ],
		[AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>
#ifdef	HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif
#include <sys/socket.h>
#include <sys/uio.h>],
			[sendfile(0, 0, (void *)0, 0);]),
			AC_MSG_RESULT([yes (Linux-style)])
			AC_DEFINE(HAVE_LINUX_SENDFILE, [],
				[Define to 1 if you have the Linux-style 'sendfile' function]),
			AC_MSG_RESULT([no])
			)]
		)
	])

dnl XS_PRINT_AS(type, define)
AC_DEFUN([XS_PRINT_TYPE], [
	AC_MSG_CHECKING([how to print $1])
	AC_RUN_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>],
		[return 8 * sizeof($1);]),
		[sz=0],
		[sz=$?])
	AC_RUN_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>],
		[$1 x = ($1)-1; return x < ($1)0;]),
		[val=PRIu$sz],
		[val=PRId$sz])
	AC_DEFINE_UNQUOTED($2, [$val], [Define how to print `$1'])
	AC_DEFINE_UNQUOTED($2x, [PRIx$sz], [Define how to print `$1' in hex])
	AC_MSG_RESULT([$val])
	])

dnl XS_DEF_MAX(type, define)
AC_DEFUN([XS_DEF_MAX], [
	AC_MSG_CHECKING([max value of $1])
	AC_RUN_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>
#include <sys/limits.h>],
		[return !$2;]),
		AC_MSG_RESULT([$2]), [
		AC_RUN_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>],
			[$1 x = ($1)-1; int s = 8 * sizeof($1);
			 return (x < ($1)0) ? s-1 : s;]),
			[sz=0],
			[sz=$?])
		val=$(( (1 << $sz) - 1))
		AC_DEFINE_UNQUOTED([$2], [$val], [Max value of `$1'])
		AC_MSG_RESULT([(1 << $sz) - 1])
		])
	])

