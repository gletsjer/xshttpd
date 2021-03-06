dnl Process this file with autoconf to produce a configure script.
AC_INIT([xshttpd],[37b35])
SERVER_IDENT="xs-httpd/3.7 beta/0.35"
AS_SHELL_SANITIZE
AC_CONFIG_SRCDIR([src/httpd.c])
AC_CONFIG_LIBOBJ_DIR([libcompat])
AC_CONFIG_AUX_DIR([aux])
AC_LANG(C)
AM_INIT_AUTOMAKE([foreign no-define silent-rules dist-bzip2 no-dist-gzip])
AC_DEFINE_UNQUOTED(SERVER_IDENT, "${SERVER_IDENT}", [Server version])
AC_CONFIG_HEADERS([config.h])

dnl Checks for programs.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99
AS_IF([test x$ac_cv_prog_cc_c99 = xno],
	AC_MSG_FAILURE([ISO C99 capable compiler required]))
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PATH_PROG(ppmtogif, ppmtogif, /bin/true)
AC_DEFINE_UNQUOTED(PATH_PPMTOGIF, "${ppmtogif}",
	[ppmtogif-like program used to create graphic counters])

dnl Checks for libraries.
CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/include"
LDFLAGS="${LDFLAGS} -L/usr/local/lib -Wl,-R/usr/local/lib"
httpd_cppflags=
httpd_cflags=
httpd_ldadd=

dnl Checks for header files.
AC_SYS_LARGEFILE
AC_CHECK_HEADERS([err.h getopt.h util.h sys/param.h sys/sendfile.h], [], [], [[]])
AC_CHECK_HEADERS([sys/syslimits.h libutil.h], [], [], [#include <sys/cdefs.h>
#include <sys/types.h>
#include <time.h>
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_OFF_T
AC_TYPE_SSIZE_T
AC_CHECK_TYPES([socklen_t, sa_family_t, in_addr_t, in_port_t, struct sockaddr_storage],,,
	[#include <sys/types.h>
#include <sys/socket.h>])
dnl XS_PRINT_TYPE(uid_t, PRIuid)
XS_PRINT_TYPE(pid_t, PRIpid)
XS_PRINT_TYPE(off_t, PRIoff)

XS_DEF_MAX(int, INT_MAX)
XS_DEF_MAX(size_t, SIZE_T_MAX)
XS_DEF_MAX(off_t, OFF_MAX)

dnl Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNCS_ONCE(setpriority setresgid setresuid setrlimit setsid sigemptyset siginterrupt uname)
XS_FUNC_SENDFILE

dnl Checks for functions requiring additional libraries.
XS_FUNC_IN_LIB(socket, HAVE_SOCKET, socket, httpd)
XS_FUNC_IN_LIB(sendfile, HAVE_SENDFILE, sendfile, httpd)
XS_FUNC_IN_LIB(inet_pton, HAVE_INET_PTON, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(getaddrinfo, HAVE_GETADDRINFO, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(getnameinfo, HAVE_GETNAMEINFO, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(dlopen, HAVE_DLOPEN, dl, httpd)
XS_FUNC_IN_LIB(fparseln, HAVE_FPARSELN, util, httpd)

AS_IF([test "$ac_cv_search_fparseln" = no], [AC_LIBOBJ(fparseln)])
AC_CHECK_FUNC(asprintf,, [AC_LIBOBJ(snprintf)])
AC_CHECK_FUNC(setegid,,   [AC_LIBOBJ(seteuid)])
AC_REPLACE_FUNCS(closefrom err fgetln killpg memmem mkstemp setenv seteuid setgroups setproctitle srandomdev strlcat strcasestr strndup strlcpy strptime strsep strerror)

dnl Check in6_addr layout; must follow socket library check.
AC_CHECK_TYPES(struct in6_addr,,, [[#include <netinet/in.h>]])
AS_IF([test x$ac_cv_type_struct_in6_addr = xyes], [
	AC_CHECK_MEMBER([struct in6_addr.s6_addr32],,,
		[[#include <netinet/in.h>]])
	AS_IF([test x$ac_cv_member_struct_in6_addr_s6_addr32 = xno], [
		AH_TEMPLATE(s6_addr32, [in6_addr elements, 32-bit version])
		AC_CHECK_MEMBER([struct in6_addr._S6_un._S6_u32],
			AC_DEFINE(s6_addr32, _S6_un._S6_u32),,
			[[#include <netinet/in.h>]])
		AC_CHECK_MEMBER([struct in6_addr.__u6_addr.__u6_addr32],
			AC_DEFINE(s6_addr32, __u6_addr.__u6_addr32),,
			[[#include <netinet/in.h>]])
		])
	])

dnl Test runs for required global variables.
AC_CHECK_DECLS_ONCE([optarg, environ])
AC_CHECK_DECLS([sys_errlist],,, [[#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
]])

dnl OpenSSL is mandatory
XS_CHECK_WITH(ssl, SSL crypto support, yes)
AS_IF([test x$with_ssl != x -a x$with_ssl != xyes],
	[LDFLAGS="${LDFLAGS} -L${with_ssl}/lib"]
	[CPPFLAGS="${CPPFLAGS} -I${with_ssl}/include"])

LDADD="${LDADD} -lcrypto"
XS_FUNC_IN_LIB(SSL_version, HAVE_SSL, ssl, httpd, [-lcrypto])
AS_IF([test "$ac_cv_search_SSL_version" = no],
	AC_MSG_ERROR([Cannot find required OpenSSL library]))

XS_FUNC_IN_LIB(OPENSSL_config, HAVE_OPENSSL_CONFIG, ssl, httpd, [-lcrypto])
XS_FUNC_IN_LIB(SSL_CTX_use_serverinfo_file, HAVE_OPENSSL_SERVERINFO, ssl, httpd, [-lcrypto])

dnl Using crypt from crypt?
XS_FUNC_IN_LIB(crypt, HAVE_CRYPT, crypt, dummy,, [
	AC_MSG_CHECKING([whether crypt(3) supports SHA-512])
	AC_RUN_IFELSE([AC_LANG_PROGRAM([#include <crypt.h>],
		[char *x=crypt("foo", "\$6\$0123456789012345"), *y=crypt("foo", x);
		if (*(x+3+16) != '\$') return 1;
		while (*x) if (*x++ != *y++) return 2;
		return 0;])], [
		AC_MSG_RESULT([yes])
		LDADD="${LDADD} -lcrypt"
		AC_DEFINE([USE_CRYPT], 1, [Prefer crypt(3) over DES_crypt(3)])
		AC_DEFINE([HAVE_CRYPT_SHA512], 1, [crypt(3) supports SHA-512])
		AC_DEFINE([CRYPT_ID], 6, [Chosen crypt(3) algorithm])
		AC_DEFINE([CRYPT_SALT_LEN], 16, [Length of salt for crypt(3)]),
		AC_MSG_RESULT([no])
		], [
		AC_DEFINE([CRYPT_SALT_LEN], 2, [Length of salt for crypt(3)])
		])
	], [
	AC_DEFINE([CRYPT_SALT_LEN], 2, [Length of salt for crypt(3)])
	])

dnl User specified additional (non-system) libraries.
XS_CHECK_WITH(pcre, PCRE support, yes, [XS_TRY_CONFIG(pcre, httpd)])

XS_CHECK_WITH(curl, CURL transfer support, no, [XS_TRY_CONFIG(curl, httpd)])

#XS_CHECK_WITH(ssi, Server Side Include support, yes, [modules="${modules} ssi"])

XS_CHECK_WITH(gzip, GZIP support, yes, [
	XS_FUNC_IN_LIB(gzopen, HAVE_GZIP, z, gzip,, [
		modules="${modules} gzip compress"
		AC_SUBST(gzip_cflags)
		AC_SUBST(gzip_ldadd)
		], [XS_FATAL(gzip)])
	])

XS_CHECK_WITH(bzip2, BZIP2 support, yes, [
	XS_FUNC_IN_LIB(BZ2_bzopen, HAVE_BZIP2, bz2, bzip2,, [
		modules="${modules} bzip2"
		AC_SUBST(bzip2_cflags)
		AC_SUBST(bzip2_ldadd)
		], [XS_FATAL(bzip2)])
	])

XS_CHECK_WITH(ldap, LDAP authentication support, no, [
	XS_FUNC_IN_LIB(ldap_initialize, HAVE_LDAP, ldap, ldap,, [
		modules="${modules} ldap"
		AC_SUBST(ldap_cflags)
		AC_SUBST(ldap_ldadd)
		], [XS_FATAL(ldap)])
	])

XS_CHECK_WITH(magic, Magic MIME detection support, yes, [
	XS_FUNC_IN_LIB(magic_open, HAVE_MAGIC, magic, magic,, [
		modules="${modules} magic"
		AC_SUBST(magic_cflags)
		AC_SUBST(magic_ldadd)
		], [XS_FATAL(magic)])
	])

XS_CHECK_WITH(rpaf, Reverse Proxy Add Forward, yes, [
		modules="${modules} rpaf"
		AC_SUBST(rpaf_cflags)
		AC_SUBST(rpaf_ldadd)
	])

XS_CHECK_WITH(htcpcp, Hyper Text Coffee Pot Control Protocol, yes, [
		modules="${modules} htcpcp"
		AC_SUBST(htcpcp_cflags)
		AC_SUBST(htcpcp_ldadd)
	])

XS_CHECK_WITH(perl, PERL persistent interpreter, no, [
	AC_PATH_PROG(perlpath, perl)
	AS_IF([test -n "${perlpath}"], [
		modules="${modules} perl"
		AC_SUBST(perl_cflags, ["`${perlpath} -MExtUtils::Embed -e ccopts`"])
		AC_SUBST(perl_ldadd, ["`${perlpath} -MExtUtils::Embed -e ldopts`"])
		], [XS_FATAL(perl)])
	AC_MSG_WARN([Internal Perl interpreter is still EXPERIMENTAL])
	])

XS_CHECK_WITH(ruby, Ruby interpreter, no, [
	AC_PATH_PROG(rubypath, ruby)
	AS_IF([test -n "${rubypath}"], [
		modules="${modules} ruby"
		AC_SUBST(ruby_cflags)
dnl		AC_SUBST(ruby_cflags, [-I"`${rubypath} -r mkmf -e 'print ($hdrdir)'`"])
		AC_SUBST(ruby_ldadd, [`${rubypath} -r mkmf -e 'print %&-L#{Config.expand($libdir)} -l#{CONFIG["RUBY_SO_NAME"]}&'`])
		], [XS_FATAL(ruby)])
	AC_MSG_WARN([Internal Ruby interpreter is still EXPERIMENTAL])
	])

XS_CHECK_WITH(python, Python interpreter, no, [
	XS_TRY_CONFIG(python, python)
	modules="${modules} python"
	AC_SUBST(python_cflags)
	AC_SUBST(python_ldadd)
	AC_MSG_WARN([Internal Python interpreter is still EXPERIMENTAL])
	])

#XS_CHECK_WITH(php, PHP interpreter, no, [
#dnl	XS_TRY_CONFIG(php, php)
#	modules="${modules} php"
#	AC_SUBST(php_cflags, ["-I/usr/local/include/php -I/usr/local/include/php/Zend -I/usr/local/include/php/main -I/usr/local/include/php/TSRM"])
#	AC_SUBST(php_ldadd, ["-L/usr/local/lib -lphp4"])
#	AC_MSG_WARN([Internal PHP interpreter is still EXPERIMENTAL])
#	])

dnl Berkely DB
XS_CHECK_WITH(db, Berkely DB support, no, [
	AS_IF([test x$withval = xyes], 
		[db_ldadd="-ldb"],
		[db_ldadd="-l${withval}"])
	dnl Check for include and library path
	AC_ARG_WITH([db-include-dir],,
			[db_cflags="-I${withval}"],
			[])
	AC_ARG_WITH([db-libdir],,
			[db_ldadd="-L${withval} ${db_ldadd}"],
			[])
	dnl Only check for db.h if we are linking with BDB
	CFLAGS_BAK="${CFLAGS}"
	CFLAGS="${CFLAGS} ${db_cflags}"
	AC_CHECK_HEADERS([db.h], [], [], [])
	CFLAGS="${CFLAGS_BAK}"
	unset CFLAGS_BAK
	AC_SUBST(db_cflags)
	AC_SUBST(db_ldadd)
	])

AC_MSG_CHECKING([if you want configuration preprocessing])
withval=
AC_ARG_WITH(preprocessor, [[
Extra options:
]AS_HELP_STRING([--with-preprocessor],
		[optional configuration preprocessor (none)])],
	[AC_MSG_RESULT([${withval:-no}])
	 AS_IF([test x$withval = xyes], [withval=m4])
	 AS_IF([test x$withval != xno], [
		 AC_PATH_PROG(preprocessor, $withval)
		 AS_IF([test x$preprocessor != x], [
			AC_DEFINE_UNQUOTED(PATH_PREPROCESSOR, "${preprocessor}",
				[preprocessor used to parse configuration files])
			], [XS_FATAL(preprocessor)])
		])
	 ], AC_MSG_RESULT(${withval:-no}))


dnl The default group and user ID of the WWW server. It assumes this group
dnl and user ID when a page or cgi-binary is requested that is not in a
dnl user's home directory. Typically this would be 'nobody' and 'nogroup',
dnl but you can also make a separate user and group id, for example 'http'
dnl and 'www'. Note that this user should be able to read the webserver data,
dnl but not able to overwrite your data - nor should it be able to write
dnl logfiles

AC_MSG_CHECKING([if you want custom running privileges])
withval=
AC_ARG_WITH(userid,
	AS_HELP_STRING([--with-userid],
		[optional effective user ID (nobody:nogroup)]),
	[AC_MSG_RESULT([${withval:-nobody:nogroup}])
	 uid="${withval%%:*}"
	 test "${uid}" = "${withval}" || gid="${withval#*:}"],
	AC_MSG_RESULT([default (nobody:nogroup)]))
AC_DEFINE_UNQUOTED(HTTPD_USERID, "${uid:-nobody}", [Effective user ID])
AC_DEFINE_UNQUOTED(HTTPD_GROUPID, "${gid:-nogroup}", [Effective group ID])

dnl Select directory layout 
hier=xs
AC_MSG_CHECKING([for --enable-hier])
AC_ARG_ENABLE(hier,
	AS_HELP_STRING([--enable-hier=[xs|bsd|gnu]], [set hierarchy layout]), [
	hier=${enable_hier}
	AC_MSG_RESULT(${enable_hier})
	], AC_MSG_RESULT(${hier}))
[eval $(sed '1,/^\['${hier}'\]$/d; /^$/,$d; s/		*//; s/=/='"'"'/; s/$/'"'"'/' ${srcdir}/dirs.conf)]

dnl Various installation directories
htmldir='$(wwwdir)/htdocs'
phexecdir='$(wwwdir)/cgi-bin'
phicondir='$(shdatadir)/icons'
fontdir='$(shdatadir)/gfxcount'
XS_ARG_DIRS(www bin man config shdata contrib font html log module phexec phicon run db)

dnl User may tweak compilation behaviour.
XS_ARG_DEFAULT(warnings, HAVE_GDB, no, [enable extra compiler warnings])
AS_IF([test x${enable_warnings} != xno], [
	CFLAGS="${CFLAGS} -g -ggdb -O2 -fsigned-char -fshort-enums -funroll-loops -pedantic -pipe -Wall -W -Wpointer-arith -Wshadow -Wbad-function-cast -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Wformat -Wformat-security -Wcomment -Wchar-subscripts -Wcast-align -Waggregate-return -Wnested-externs -Winline -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wunreachable-code -Wno-format-zero-length"
	AS_IF([test x${enable_warnings} = xextra],
		[CFLAGS="${CFLAGS} -Wconversion -Wpadded"])
	])

XS_ARG_DEFAULT(ssp, HAVE_SSP, yes, [enable stack smashing protector])
AS_IF([test x${enable_ssp} = xyes], [
	AC_MSG_CHECKING([whether ${CC%% *} supports stack protection...])
	TCFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} -fstack-protector-all -Wstack-protector"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [int i = 0;])],
		AC_MSG_RESULT([yes]),
		AC_MSG_RESULT([no])
		CFLAGS="${TCFLAGS}")
	])

dnl write modules.c
for m in ${modules}
do
	mod_name="${mod_name} \"${m}\","
done
mod_name="{ ${mod_name# } NULL }"
AM_CONDITIONAL(MOD_PERL,   [echo "${modules}" | grep -q perl])
AM_CONDITIONAL(MOD_PYTHON, [echo "${modules}" | grep -q python])
AM_CONDITIONAL(MOD_RUBY,   [echo "${modules}" | grep -q ruby])
AM_CONDITIONAL(MOD_PHP,    [echo "${modules}" | grep -q php])
AM_CONDITIONAL(MOD_LDAP,   [echo "${modules}" | grep -q ldap])
AM_CONDITIONAL(MOD_GZIP,   [echo "${modules}" | grep -q gzip])
AM_CONDITIONAL(MOD_BZIP2,  [echo "${modules}" | grep -q bzip2])
AM_CONDITIONAL(MOD_MAGIC,  [echo "${modules}" | grep -q magic])
AM_CONDITIONAL(MOD_RPAF,   [echo "${modules}" | grep -q rpaf])
AM_CONDITIONAL(MOD_HTCPCP, [echo "${modules}" | grep -q htcpcp])
#AM_CONDITIONAL(MOD_SSI,   [echo "${modules}" | grep -q ssi])
AC_DEFINE_UNQUOTED(MODULES, [${mod_name}], [Modules enabled during compilation])

dnl Generate configure output.
LIBS="${LDADD}"
AC_SUBST(httpd_cppflags)
AC_SUBST(httpd_cflags)
AC_SUBST(httpd_ldadd)
AC_SUBST(SERVER_IDENT)
AC_SUBST(mod_decl)
AC_SUBST(mod_list)
AC_SUBST(mod_name)
AC_CONFIG_FILES([Makefile config/Makefile contrib/Makefile fonts/Makefile icons/Makefile man/Makefile libcompat/Makefile src/Makefile])
AC_OUTPUT
