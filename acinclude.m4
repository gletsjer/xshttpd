dnl Make my life easier
AC_DEFUN(AC_ARG_DEFAULT, [
	AC_MSG_CHECKING(for --enable-$1)
	AC_ARG_ENABLE($1,
		[$4],
		AC_MSG_RESULT(${enable_$1}),
		enable_$1=$3
		 AC_MSG_RESULT($3))
	if test ${enable_$1} = "yes" ; then AC_DEFINE($2) fi
	])

AC_DEFUN(AC_SHOW_HELP, [
	AC_DIVERT_PUSH(AC_DIVERSION_NOTICE)
	ac_help="$ac_help
[$1]"
	AC_DIVERT_POP()
	])

dnl AC_DEFUN(ac_ARG_DIR, [
dnl 	AC_ARG_WITH($1,
dnl 		[  --with-$1=PATH	  directory to use for $2 [ROOTDIR/$2]],
dnl 		$1=${withval},
dnl 		$1=${rootdir}/$2)
dnl 	])
AC_DEFUN(AC_ARG_DIR, $1=${rootdir}/$2)

AC_DEFUN(AC_NEED_CONST, [
	AC_MSG_CHECKING("for $1")
	AC_TRY_RUN([
#include <$3>
int main() { return $1, 0; }
],
		AC_MSG_RESULT(found),
		AC_MSG_RESULT(will use my own)
		AC_DEFINE($2),
		AC_MSG_RESULT(unknown))
	])

AC_DEFUN(AC_NEED_CONST2, [
	AC_MSG_CHECKING("for $1")
	AC_TRY_RUN([
#include <$3>
#include <$4>
int main() { return $1, 0; }
],
		AC_MSG_RESULT(found),
		AC_MSG_RESULT(will use my own)
		AC_DEFINE($2),
		AC_MSG_RESULT(unknown))
	])

