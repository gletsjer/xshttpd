dnl Make my life easier
AC_DEFUN(AC_ARG_DEFAULT, [
	AC_MSG_CHECKING(for --enable-$1)
	AC_ARG_ENABLE($1,
		[$3],
		AC_MSG_RESULT(${enable_$1}),
		enable_$1=yes
		 AC_MSG_RESULT(yes))
	if test ${enable_$1} = "yes" ; then AC_DEFINE($2) fi
	])

AC_DEFUN(AC_ARG_DIR, [
	AC_ARG_WITH($1,
		[  --with-$1=PATH	  directory to use for $2 [ROOTDIR/$2]],
		$1=${withval},
		$1=${rootdir}/$2)
	])

AC_DEFUN(AC_NEED_CONST, [
	AC_MSG_CHECKING("for $1")
	AC_TRY_RUN([
#include <$2>
int main() { return $1, 0; }
],
		AC_MSG_RESULT(found),
		AC_MSG_RESULT(will use my own)
		AC_DEFINE($3),
		AC_MSG_RESULT(unknown))
	])

