dnl Process this file with autoconf to produce a configure script.
AC_INIT([xshttpd],[37b04])
SERVER_IDENT="xs-httpd/3.7 beta/0.04"
AS_SHELL_SANITIZE
AC_CONFIG_SRCDIR(src/httpd.c)
AC_CONFIG_LIBOBJ_DIR(libcompat)
AM_INIT_AUTOMAKE([foreign no-define dist-bzip2 no-dist-gzip])
AC_DEFINE_UNQUOTED(SERVER_IDENT, "${SERVER_IDENT}", [Server version])
AC_CONFIG_HEADERS([config.h])

dnl Checks for programs.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99
AS_IF([test x$ac_cv_prog_cc_c99 = xno],
	AC_MSG_FAILURE([ISO C99 capable compiler required]))
AC_PROG_INSTALL
dnl AC_LIBTOOL_DLOPEN
dnl AC_PROG_LIBTOOL
AC_PROG_RANLIB
AC_PATH_PROG(ppmtogif, ppmtogif, /bin/true)
AC_DEFINE_UNQUOTED(PATH_PPMTOGIF, "${ppmtogif}",
	[ppmtogif-like program used to create graphic counters])

dnl Checks for libraries.
CFLAGS="${CFLAGS} -I/usr/local/include -I/usr/include"
LDFLAGS="${LDFLAGS} -L/usr/local/lib -Wl,-R/usr/local/lib"
httpd_cflags="${CFLAGS}"
libxs_cflags="${CFLAGS}"
httpd_ldflags="${LDFLAGS}"
libxs_ldflags="${LDFLAGS}"

dnl Checks for header files.
AC_SYS_LARGEFILE
AC_CHECK_HEADERS([err.h getopt.h util.h sys/param.h sys/select.h sys/sendfile.h], [], [], [[]])
AC_CHECK_HEADERS([sys/syslimits.h libutil.h sys/resource.h sys/mman.h], [], [], [#include <sys/cdefs.h>
#include <sys/types.h>
#include <time.h>
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_OFF_T
AC_TYPE_SSIZE_T
AC_CHECK_TYPES([socklen_t, sa_family_t, in_addr_t, in_port_t],,,
	[#include <sys/types.h>
#include <sys/socket.h>])
AC_CHECK_TYPES([time_t],, AC_DEFINE(time_t, int, [What time looks like]),
	[#include <sys/types.h>
#include <time.h>])
XS_PRINT_TYPE(uid_t, PRIuid)
XS_PRINT_TYPE(pid_t, PRIpid)
XS_PRINT_TYPE(off_t, PRIoff)
XS_PRINT_TYPE(time_t, PRItime)

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
XS_FUNC_IN_LIB(inet_aton, HAVE_INET_ATON, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(inet_pton, HAVE_INET_PTON, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(getaddrinfo, HAVE_GETADDRINFO, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(getnameinfo, HAVE_GETNAMEINFO, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(dlopen, HAVE_DLOPEN, dl, httpd)
XS_FUNC_IN_LIB(fparseln, HAVE_FPARSELN, util, libxs)

AS_IF([test "$ac_cv_search_inet_aton" = no], [AC_LIBOBJ(inet_aton)])
AS_IF([test "$ac_cv_search_fparseln" = no], [AC_LIBOBJ(fparseln)])
AC_CHECK_FUNC(asprintf,, [AC_LIBOBJ(snprintf)])
AC_CHECK_FUNC(setegid,,   [AC_LIBOBJ(seteuid)])
AC_REPLACE_FUNCS(closefrom err fgetln killpg memmem mkstemp setenv seteuid setgroups setproctitle srandomdev strlcat strcasestr strlcpy strptime strsep)

dnl Check in6_addr layout; must follow socket library check.
AC_CHECK_TYPES(struct in6_addr,,, [#include <netinet/in.h>])
AS_IF([test x$ac_cv_type_struct_in6_addr = xyes], [
	AC_CHECK_MEMBER([struct in6_addr.s6_addr32],,,
		[#include <netinet/in.h>])
	AS_IF([test x$ac_cv_member_struct_in6_addr_s6_addr32 = xno], [
		AH_TEMPLATE(s6_addr32, [in6_addr elements, 32-bit version])
		AC_CHECK_MEMBER([struct in6_addr._S6_un._S6_u32],
			AC_DEFINE(s6_addr32, _S6_un._S6_u32),,
			[#include <netinet/in.h>])
		AC_CHECK_MEMBER([struct in6_addr.__u6_addr.__u6_addr32],
			AC_DEFINE(s6_addr32, __u6_addr.__u6_addr32),,
			[#include <netinet/in.h>])
		])
	])

dnl Test runs for required global variables.
AC_CHECK_DECLS_ONCE([sys_errlist, optarg, environ])

dnl OpenSSL is mandatory
XS_CHECK_WITH(ssl, SSL crypto support, yes)
AS_IF([test x$with_ssl != x -a x$with_ssl != xyes],
	[ssllib="-L${with_ssl}/lib -lcrypto"]
	[sslinc="-I${with_ssl}/include"],
	[ssllib="-lcrypto"])

XS_FUNC_IN_LIB(SSL_version, HAVE_SSL, ssl, xssl, [${ssllib}])
AS_IF([test "$ac_cv_search_SSL_version" = no],
	AC_MSG_ERROR([Cannot find required OpenSSL library]))

XS_FUNC_IN_LIB(OPENSSL_config, HAVE_OPENSSL_CONFIG, ssl, x, [${ssllib}])
libxs_cflags="${libxs_cflags} ${sslinc}"
libxs_ldflags="${libxs_ldflags} ${ssllib}"
httpd_ldflags="${httpd_ldflags} ${xssl_ldflags}"

dnl User specified additional (non-system) libraries.
XS_CHECK_WITH(pcre, PCRE support, yes, [XS_TRY_CONFIG(pcre, httpd)])

XS_CHECK_WITH(curl, CURL transfer support, no, [XS_TRY_CONFIG(curl, httpd)])

XS_CHECK_WITH(gzip, GZIP support, yes, [
	XS_FUNC_IN_LIB(gzopen, HAVE_GZIP, z, gzip)
	AC_SUBST(gzip_cflags)
	AC_SUBST(gzip_ldflags)
	test x$ac_cv_search_ldap_initialize != xno && modules="${modules} gzip compress"
	])

XS_CHECK_WITH(bzip2, BZIP2 support, no, [
	XS_FUNC_IN_LIB(BZ2_bzopen, HAVE_BZIP2, bz2, bzip2)
	AC_SUBST(bzip2_cflags)
	AC_SUBST(bzip2_ldflags)
	test x$ac_cv_search_ldap_initialize != xno && modules="${modules} bzip2"
	])

XS_CHECK_WITH(ldap, LDAP authentication support, no, [
	XS_FUNC_IN_LIB(ldap_initialize, HAVE_LDAP, ldap, ldap)
	AC_SUBST(ldap_cflags)
	AC_SUBST(ldap_ldflags)
	test x$ac_cv_search_ldap_initialize != xno && modules="${modules} ldap"
	])

XS_CHECK_WITH(perl, PERL persistent interpreter, no, [
	AC_PATH_PROG(perlpath, perl)
	AS_IF([test -n "${perlpath}"], [
		modules="${modules} perl"
		AC_SUBST(perl_cflags, ["`${perlpath} -MExtUtils::Embed -e ccopts`"])
		AC_SUBST(perl_ldflags, ["`${perlpath} -MExtUtils::Embed -e ldopts`"])
		])
	AC_MSG_WARN([Internal Perl interpreter is still EXPERIMENTAL])
	])

XS_CHECK_WITH(python, Python interpreter, no, [
	XS_TRY_CONFIG(python, python, [modules="${modules} python"], [
		XS_TRY_CONFIG([python2.5], python, 
			[modules="${modules} python"])
		])
	AC_MSG_WARN([Internal Python interpreter is still EXPERIMENTAL])
	AC_SUBST(python_cflags)
	AC_SUBST(python_ldflags)
	])

XS_CHECK_WITH(ruby, Ruby interpreter, no, [
	XS_FUNC_IN_LIB(ruby_run, HAVE_RUBY, [ruby18], ruby)
	test x$ac_cv_search_ruby_run != xno && modules="${modules} ruby"
	AC_SUBST(ruby_cflags)
	AC_SUBST(ruby_ldflags)
	AC_MSG_WARN([Internal Ruby interpreter is still EXPERIMENTAL])
dnl	rubyhdr="`ruby -r mkmf -e 'print ($hdrdir)'`/ruby.h"
dnl	AC_DEFINE_UNQUOTED(RUBY_HDR, "${rubyhdr}", [Ruby include file])
	])

AC_MSG_CHECKING([if you want configuration preprocessing])
withval=
AC_ARG_WITH(preprocessor, [
Extra options:
]AS_HELP_STRING([--with-preprocessor],
		[optional configuration preprocessor (none)]),
	[AC_MSG_RESULT(${withval:-no})
	 AS_IF([test x$withval = xyes], [withval=m4])
	 AS_IF([test x$withval != xno], [
		 AC_PATH_PROG(preprocessor, $withval)
		 AS_IF([test x$preprocessor != x],
			[AC_DEFINE_UNQUOTED(PATH_PREPROCESSOR, "${preprocessor}",
				[preprocessor used to parse configuration files])],
			[AC_MSG_FAILURE([--with-preprocessor was given, but command not found])])
		])
	 ], AC_MSG_RESULT(${withval:-no}))

dnl Main root directory, optionally supplied by user.
dnl Set may be delayed untill 'make' stage, becasue ${prefix} is delayed.
withval=
AC_ARG_WITH(rootdir,
	AS_HELP_STRING([--with-rootdir=DIR],
		[directory to install data files @<:@LIBDIR/httpd@:>@]),
	rootdir="${withval}",
	rootdir='${prefix}/lib/httpd')
AC_SUBST(rootdir)

dnl Various installation directories - relative to ${rootdir}.
XS_ARG_DIR(config,  CONFIG_DIR, [conf])
XS_ARG_DIR(cgi,     CGI_DIR,    [cgi-bin])
XS_ARG_DIR(phexec,  PHEXEC_DIR, [cgi-bin])
XS_ARG_DIR(contrib, CONTRIB_DIR,[contrib])
XS_ARG_DIR(font,    FONT_DIR,   [gfxcount])
XS_ARG_DIR(html,    HTML_DIR,   [htdocs])
XS_ARG_DIR(icon,    ICON_DIR,   [icons])
XS_ARG_DIR(phicon,  PHICON_DIR, [icons])
XS_ARG_DIR(log,     LOG_DIR,    [logs])
XS_ARG_DIR(module,  MODULE_DIR, [module])

dnl User may tweak compilation behaviour.
XS_ARG_DEFAULT(warnings, HAVE_GDB, no, [enable extra compiler warnings])
AS_IF([test x${enable_warnings} != xno], [
	CFLAGS="${CFLAGS} -g -ggdb -O2 -fsigned-char -fshort-enums -funroll-loops -pedantic -trigraphs -pipe -Wall -W -Wpointer-arith -Wshadow -Wbad-function-cast -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Wformat -Wformat-security -Wcomment -Wchar-subscripts -Wcast-align -Waggregate-return -Wnested-externs -Winline -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wunreachable-code"
	AS_IF([test x${enable_warnings} = xextra],
		[CFLAGS="${CFLAGS} -Wconversion -Wpadded"])
	])

XS_ARG_DEFAULT(ssp, HAVE_SSP, yes, [enable stack smashing protector])
AS_IF([test x${enable_ssp} = xyes], [
	AC_MSG_CHECKING([whether ${CC%% *} supports stack protection...])
	TCFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} -fstack-protector-all -Wstack-protector"
	AC_COMPILE_IFELSE(AC_LANG_SOURCE([int i = 0;]),
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
AM_CONDITIONAL(MOD_LDAP,   [echo "${modules}" | grep -q ldap])
AM_CONDITIONAL(MOD_GZIP,   [echo "${modules}" | grep -q gzip])
AM_CONDITIONAL(MOD_BZIP2,   [echo "${modules}" | grep -q bzip2])
AC_DEFINE_UNQUOTED(MODULES, [${mod_name}], [Modules enabled during compilation])

dnl Generate configure output.
AC_SUBST(libxs_ldflags)
AC_SUBST(libxs_cflags)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_SUBST(SERVER_IDENT)
AC_SUBST(mod_decl)
AC_SUBST(mod_list)
AC_SUBST(mod_name)
AC_CONFIG_FILES([Makefile config/Makefile contrib/Makefile fonts/Makefile icons/Makefile man/Makefile libcompat/Makefile src/Makefile man/httpd.1])
AC_OUTPUT
