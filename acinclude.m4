dnl Make my life easier
AC_DEFUN([XS_ARG_DEFAULT], [
	AC_MSG_CHECKING(for --enable-$1)
	AC_ARG_ENABLE($1,
		AC_HELP_STRING([--enable-$1], [$4 ($3)]),
		AC_MSG_RESULT(${enable_$1}),
		enable_$1=$3
		AC_MSG_RESULT($3))
	if test ${enable_$1} = "yes" -a -n "$2" ; then AC_DEFINE($2,, [$4]) fi
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
AC_DEFUN([XS_ARG_DIR], $1=${rootdir}/$2)

AC_DEFUN([XS_NEED_CONST], [
	AC_MSG_CHECKING("for $1")
	AC_TRY_RUN([
#include <$3>
int main() { return $1, 0; }
],
		AC_MSG_RESULT(found),
		AC_MSG_RESULT(will use my own)
		AC_DEFINE($2,, [define if not declared in system]),
		AC_MSG_RESULT(unknown))
	])

AC_DEFUN([XS_NEED_CONST2], [
	AC_MSG_CHECKING("for $1")
	AC_TRY_RUN([
#include <$3>
#include <$4>
int main() { return $1, 0; }
],
		AC_MSG_RESULT(found),
		AC_MSG_RESULT(will use my own)
		AC_DEFINE($2,, [define if not declared in system]),
		AC_MSG_RESULT(unknown))
	])

# AC_FUNC_IN_LIB(function, define, library, buildprog, extra-lib)
AC_DEFUN([XS_FUNC_IN_LIB], [
	AC_CHECK_FUNCS($1,
		AC_DEFINE($2,, [Define to 1 if you have the `$3' functions.]),
		[AC_CHECK_LIB($3,
			$1,
			AC_DEFINE($2) $4_ldflags="${$4_ldflags} -l$3",
			,
			$5)
		])
	])

# XS_CHECK_WITH(function, desc, default)
AC_DEFUN([XS_CHECK_WITH], [
	AC_MSG_CHECKING([if you want $2])
	AC_ARG_WITH($1,
		AC_HELP_STRING([--with-$1], [$2 ($3)]),
		AC_MSG_RESULT($with_$1),
		with_$1=$3
		AC_MSG_RESULT($3))
	])
