dnl Make my life easier
# XS_ARG_DEFAULT(option, define, def.value, help string)
AC_DEFUN([XS_ARG_DEFAULT], [
	AC_MSG_CHECKING(for --enable-$1)
	AC_ARG_ENABLE($1,
		AC_HELP_STRING([--enable-$1], [$4 ($3)]),
		AC_MSG_RESULT(${enable_$1}),
		enable_$1=$3
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
	AH_TEMPLATE($2, [Define if you have the `$2' functions.])
	AC_SEARCH_LIBS($1, $3, [AC_DEFINE($2)],, $5)
	AS_IF([test -n "${LIBS}"], [$4_ldflags="${$4_ldflags} ${LIBS}"])
	])

# XS_CHECK_WITH(function, desc, default)
AC_DEFUN([XS_CHECK_WITH], [
	AC_MSG_CHECKING([if you want $2])
	AC_ARG_WITH($1,
		AC_HELP_STRING([--with-$1], [$2 ($3)]),
		AC_MSG_RESULT(${with_$1}),
		with_$1=$3
		AC_MSG_RESULT($3))
	])

# XS_TRY_CONFIG(path, buildprog)
AC_DEFUN([XS_TRY_CONFIG], [
	unset progpath ac_cv_path_progpath
	AC_PATH_PROG(progpath, $1-config)
	AS_IF([test -n "${progpath}"], [
		$2_cflags="${$2_cflags} `${progpath} --cflags`"
		$2_ldflags="${$2_ldflags} `${progpath} --libs`"
	])])

