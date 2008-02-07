dnl Process this file with autoconf to produce a configure script.
AC_INIT(xshttpd, 36b03)
SERVER_IDENT="xs-httpd/3.6 beta/0.03"
AS_SHELL_SANITIZE
AC_CONFIG_SRCDIR(src/httpd.c)
AC_CONFIG_LIBOBJ_DIR(libcompat)
AM_INIT_AUTOMAKE([foreign no-define dist-bzip2 no-dist-gzip])
AC_DEFINE_UNQUOTED(SERVER_IDENT, "${SERVER_IDENT}", [Server version])
AC_CONFIG_HEADERS([config.h])

dnl Checks for programs.
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = no
then
	AC_MSG_ERROR([ISO C99 capable compiler required])
fi
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PATH_PROG(ppmtogif, ppmtogif, /bin/true)
AC_DEFINE_UNQUOTED(PATH_PPMTOGIF, "${ppmtogif}",
	[ppmtogif-like program used to create graphic counters])

dnl Checks for libraries.
CFLAGS="${CFLAGS} -I/usr/local/include -I/usr/include"
LDFLAGS="${LDFLAGS} -L/usr/local/lib"
httpd_cflags="${CFLAGS}"
libxs_cflags="${CFLAGS}"
httpd_ldlags="${LDLAGS}"
libxs_ldlags="${LDLAGS}"

dnl Checks for header files.
AC_GNU_SOURCE
AC_SYS_LARGEFILE
AC_CHECK_HEADERS([crypt.h err.h getopt.h memory.h sys/mman.h sys/param.h sys/resource.h sys/select.h], [], [], [[]])
AC_CHECK_HEADERS([sys/syslimits.h], [], [], [#include <sys/cdefs.h>
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T
AC_TYPE_OFF_T
AC_CHECK_TYPES([socklen_t, sa_family_t],,, [#include <sys/types.h>
#include <sys/socket.h>])

dnl Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNCS_ONCE(setpriority setresgid setresuid setrlimit setsid sigemptyset siginterrupt uname)

dnl Checks for functions requiring additional libraries.
XS_FUNC_IN_LIB(socket, HAVE_SOCKET, socket, httpd)
XS_FUNC_IN_LIB(inet_aton, HAVE_INET_ATON, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(inet_pton, HAVE_INET_PTON, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(getaddrinfo, HAVE_GETADDRINFO, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(getnameinfo, HAVE_GETNAMEINFO, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(crypt, HAVE_CRYPT, crypt, libxs)
XS_FUNC_IN_LIB(MD5Data, HAVE_LIBMD, md, libxs)
if test "$ac_cv_search_MD5Data" != no
then
	AC_DEFINE(HAVE_MD5, [], [MD5 function is available (libmd or openssl)])
fi

AS_IF([test "$ac_cv_search_inet_aton" = no], [AC_LIBOBJ(inet_aton)])
AC_CHECK_FUNC(asprintf,, [AC_LIBOBJ(snprintf)])
AC_CHECK_FUNC(setegid,,   [AC_LIBOBJ(seteuid)])
AC_REPLACE_FUNCS(closefrom err killpg memmem mkstemp seteuid setgroups setproctitle srandomdev strlcat strcasestr strlcpy strptime strsep)

dnl Check in6_addr layout; must follow socket library check.
AC_CHECK_TYPES(struct in6_addr,,, [#include <netinet/in.h>])
if test "$ac_cv_type_struct_in6_addr" = yes
then
	AC_CHECK_MEMBER([struct in6_addr.s6_addr32],,,
		[#include <netinet/in.h>])
	if test "$ac_cv_member_struct_in6_addr_s6_addr32" = no
	then
		AH_TEMPLATE(s6_addr32, [in6_addr elements, 32-bit version])
		AC_CHECK_MEMBER([struct in6_addr._S6_un._S6_u32],
			AC_DEFINE(s6_addr32, _S6_un._S6_u32),,
			[#include <netinet/in.h>])
		AC_CHECK_MEMBER([struct in6_addr.__u6_addr.__u6_addr32],
			AC_DEFINE(s6_addr32, __u6_addr.__u6_addr32),,
			[#include <netinet/in.h>])
	fi
fi

dnl Main root directory, optionally supplied by user.
dnl Set may be delayed untill 'make' stage, becasue ${prefix} is delayed.
AC_ARG_WITH(rootdir,
	AS_HELP_STRING(--with-rootdir=PATH,
		[directory to install data files (LIBDIR/httpd)]),
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
XS_ARG_DIR(log,     LOG_DIR,    [logs])

dnl User specified additional (non-system) libraries.
XS_CHECK_WITH(ssl, SSL crypto support, yes)
if test x${with_ssl} = xyes
then
	XS_FUNC_IN_LIB(SSL_version, HAVE_SSL, ssl, xssl, -lcrypto)
	if test "$ac_cv_search_SSL_version" != no
	then
		httpd_cflags="${httpd_cflags} -I/usr/local/ssl/include"
		httpd_ldflags="${httpd_ldflags} ${xssl_ldflags}"
		AC_DEFINE(HANDLE_SSL,, [Enable OpenSSL support])
		if test "$ac_cv_search_MD5Data" = no
		then
			AC_DEFINE(HAVE_MD5)
			AC_DEFINE(USE_OPENSSL_MD5,,
				[Define if you have openssl, but no MD5Data()])
			AC_LIBOBJ(MD5Data)
			libxs_ldflags="${libxs_ldflags} ${xssl_ldflags}"
		fi
		if test "$ac_cv_search_crypt" = no
		then
			AC_DEFINE(HAVE_CRYPT)
			AC_LIBOBJ(crypt)
			libxs_ldflags="${libxs_ldflags} ${xssl_ldflags}"
		fi
	else
		AC_MSG_ERROR([Cannot find libraries for --with-ssl])
	fi
fi

XS_CHECK_WITH(pcre, PCRE support, yes)
if test x${with_pcre} = xyes
then
	XS_FUNC_IN_LIB(pcre_exec, HAVE_PCRE, pcre, httpd)
	XS_TRY_CONFIG(pcre, httpd)
fi

XS_CHECK_WITH(ldap, LDAP authentication support, no)
if test x${with_ldap} = xyes
then
	XS_FUNC_IN_LIB(ldap_initialize, AUTH_LDAP, ldap, httpd)
fi

XS_CHECK_WITH(curl, CURL transfer support, no)
if test x${with_curl} = xyes
then
	XS_FUNC_IN_LIB(curl_version, HAVE_CURL, curl, httpd)
	XS_TRY_CONFIG(curl, httpd)
fi

XS_CHECK_WITH(perl, PERL persistent interpreter, no)
if test x${with_perl} = xyes
then
	AC_PATH_PROG(perlpath, perl)
	if test -n "${perlpath}"
	then
		AC_DEFINE(HAVE_PERL,, [Define this to use perl cgi environment])
		httpd_cflags="${httpd_cflags} `${perlpath} -MExtUtils::Embed -e ccopts`"
		httpd_ldflags="${httpd_ldflags} `${perlpath} -MExtUtils::Embed -e ldopts`"
	fi
fi

XS_CHECK_WITH(python, Python interpreter, no)
if test x${with_python} = xyes
then
	XS_TRY_CONFIG([python2.5], httpd)
fi

XS_CHECK_WITH(preprocessor, optional configuration preprocessor, no)
if test x${with_preprocessor} = xyes
then
	with_preprocessor=m4
fi
if test x${with_preprocessor} != xno
then
	AC_PATH_PROG(preprocessor, ${with_preprocessor})
	if test  -n "${preprocessor}"
	then
		AC_DEFINE_UNQUOTED(PATH_PREPROCESSOR, "${preprocessor}",
			[preprocessor used to parse configuration files])
	fi
fi

dnl User may tweak compilation behaviour.
XS_ARG_DEFAULT(warnings, DUMMY, no, [enable extra compiler warnings])
if test x${enable_warnings} != xno
then
	CFLAGS="${CFLAGS} -g -ggdb -O2 -fsigned-char -fshort-enums -funroll-loops -pedantic -trigraphs -pipe -Wall -W -Wpointer-arith -Wshadow -Wbad-function-cast -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Wformat -Wformat-security -Wcomment -Wchar-subscripts -Wcast-align -Waggregate-return -Wnested-externs -Winline -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wunreachable-code"
	if test x${enable_warnings} = xextra
	then
		CFLAGS="${CFLAGS} -Wconversion -Wpadded"
	fi
fi

XS_ARG_DEFAULT(ssp, DUMMY, no, [enable stack smashing protector])
if test x${enable_ssp} = xyes
then
	AC_MSG_CHECKING([whether ${CC%% *} supports stack protection...])
	TCFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} -fstack-protector-all -Wstack-protector"
	AC_COMPILE_IFELSE(AC_LANG_SOURCE([int i = 0;]),
		AC_MSG_RESULT([yes]),
		AC_MSG_RESULT([no])
		CFLAGS="${TCFLAGS}")
fi

dnl Test runs for required global variables.
AC_CHECK_DECLS_ONCE([sys_errlist, optarg, environ])

dnl Generate configure output.
AC_SUBST(libxs_ldflags)
AC_SUBST(libxs_cflags)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_SUBST(SERVER_IDENT)
AC_CONFIG_FILES([Makefile config/Makefile contrib/Makefile fonts/Makefile icons/Makefile man/Makefile libcompat/Makefile src/Makefile man/httpd.1])
AC_OUTPUT
