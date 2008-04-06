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

AC_DEFUN([XS_SHOW_HELP], [
	AC_DIVERT_PUSH(AC_DIVERSION_NOTICE)
	ac_help="$ac_help
[$1]"
	AC_DIVERT_POP()
	])

dnl AC_DEFUN([ac_ARG_DIR], [
dnl 	AC_ARG_WITH($1,
dnl 		[  --with-$1=PATH	  directory to use for $2 [ROOTDIR/$2]],
dnl 		$1=${withval},
dnl 		$1=${rootdir}/$2)
dnl 	])
AC_DEFUN([XS_ARG_DIR], [
	$1dir='${rootdir}/$3'
	AC_SUBST($1dir)
	AC_DEFINE([$2], "$3", [$1 directory])
	AS_IF([test -z "$3"],
		AC_DEFINE([$2T], []),
		AC_DEFINE([$2T], [$2 "/"],
			[$1 directory with opt. trailing slash]))
	])

# AC_FUNC_IN_LIB(function, define, library, buildprog, extra-lib)
AC_DEFUN([XS_FUNC_IN_LIB], [
	LIBS=
	AH_TEMPLATE($2, [Define to 1 if you have the `$1' function])
	AC_SEARCH_LIBS($1, $3, [AC_DEFINE($2)],, $5)
	AS_IF([test -n "${LIBS}"], [$4_ldflags="${$4_ldflags} ${LIBS} $5"])
	LIBS=
	])

# XS_CHECK_WITH(function, desc, default)
AC_DEFUN([XS_CHECK_WITH], [
	AC_MSG_CHECKING([if you want $2])
	AC_ARG_WITH($1,
		AC_HELP_STRING([--with-$1], [$2 ($3)]),
		AC_MSG_RESULT(${with_$1}),
		AS_TR_SH(with_$1)=$3
		AC_MSG_RESULT($3))
	])

# XS_TRY_CONFIG(path, buildprog)
AC_DEFUN([XS_TRY_CONFIG], [
	unset progpath ac_cv_path_progpath
	AC_PATH_PROG(progpath, $1-config)
	AS_TR_SH(xs_$1_path)="$progpath"
	AS_IF([test -n "${progpath}"],
		[$2_cflags="${$2_cflags} `${progpath} --cflags`"
		 $2_ldflags="${$2_ldflags} `${progpath} --libs`"])
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
		[return !$2_MAX;]),
		AC_MSG_RESULT([$2_MAX]), [
		AC_RUN_IFELSE(AC_LANG_PROGRAM([#include <sys/types.h>],
			[$1 x = ($1)-1; int s = 8 * sizeof($1);
			 return (x < ($1)0) ? s-1 : s;]),
			[sz=0],
			[sz=$?])
		AC_DEFINE_UNQUOTED([$2_MAX], [((1 << $sz) - 1)],
			[Max value of `$1'])
		AC_MSG_RESULT([(1 << $sz) - 1])
		])
	])

