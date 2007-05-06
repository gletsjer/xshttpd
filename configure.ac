dnl Process this file with autoconf to produce a configure script.
AC_INIT(xshttpd, 35b07)
SERVER_IDENT="xs-httpd/3.5 beta/0.07"
AC_CONFIG_SRCDIR(src/httpd.c)
AC_CONFIG_LIBOBJ_DIR(libcompat)
AM_INIT_AUTOMAKE([foreign no-define dist-bzip2 no-dist-gzip])
AC_DEFINE_UNQUOTED(SERVER_IDENT, "${SERVER_IDENT}", [Server version])
AC_CONFIG_HEADERS([config.h])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_LN_S
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
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS(alloca.h crypt.h err.h sys/exec.h getopt.h inttypes.h memory.h sys/mman.h sys/param.h sys/pstat.h sys/resource.h sys/select.h sys/syslimits.h sys/sysmips.h sys/sysnews.h sys/time.h time.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_CHECK_TYPES(socklen_t,,, [#include <sys/types.h>
#include <sys/socket.h>])

dnl Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_FUNC_SETVBUF_REVERSED
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(getaddrinfo getnameinfo mkstemp mmap setegid seteuid setpriority setresgid setresuid setrlimit setsid sigemptyset uname)

dnl Checks for functions requiring additional libraries.
XS_FUNC_IN_LIB(socket, HAVE_SOCKET, socket, httpd)
XS_FUNC_IN_LIB(inet_aton, HAVE_INET_ATON, nsl, httpd, -lsocket)
AS_IF([test "$ac_cv_search_inet_aton" = no], [AC_LIBOBJ(inet_aton)])
XS_FUNC_IN_LIB(inet_pton, HAVE_INET_PTON, nsl, httpd, -lsocket)
XS_FUNC_IN_LIB(crypt, HAVE_CRYPT, crypt, libxs)
XS_FUNC_IN_LIB(MD5Data, HAVE_MD5, md, libxs)

AC_CHECK_FUNC(asnprintf,, [AC_LIBOBJ(snprintf)])
AC_REPLACE_FUNCS(err killpg memmem setenv setgroups setproctitle strlcat strcasestr strerror strlcpy strptime strsep snprintf)

dnl Check in6_addr layout; must follow socket library check.
AC_CHECK_TYPES(struct in6_addr,,, [#include <netinet/in.h>])
if test "$ac_cv_type_struct_in6_addr" = yes
then
	AC_CHECK_MEMBER([struct in6_addr.s6_addr32],,,
		[#include <netinet/in.h>])
	if test "$ac_cv_member_struct_in6_addr_s6_addr32" = no
	then
		AH_TEMPLATE(s6_addr32,, [in6_addr elements, 32-bit version])
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
XS_ARG_DIR(config,  CONFIG_DIR, [])
XS_ARG_DIR(cgi,     CGI_DIR,    [cgi-bin])
XS_ARG_DIR(phexec,  PHEXEC_DIR, [cgi-bin])
XS_ARG_DIR(contrib, CONTRIB_DIR,[contrib])
XS_ARG_DIR(font,    FONT_DIR,   [gfxcount])
XS_ARG_DIR(html,    HTML_DIR,   [htdocs])
XS_ARG_DIR(icon,    ICON_DIR,   [htdocs/icons])
XS_ARG_DIR(log,     LOG_DIR,    [logs])

dnl User specified additional (non-system) libraries.
XS_CHECK_WITH(ssl, SSL crypto support, yes)
if test x${with_ssl} = xyes
then
	XS_FUNC_IN_LIB(SSLeay_version, HAVE_SSLEAY, crypto, xssl)
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

XS_CHECK_WITH(pcre, PCRE support, no)
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
	AC_PATH_PROG(pythonpath, [python2.5])
	if test -n "${pythonpath}"
	then
		AC_DEFINE(HAVE_PYTHON,, [Define this to use python cgi environment])
		httpd_cflags="${httpd_cflags} `${pythonpath} --cflags`"
		httpd_ldflags="${httpd_ldflags} -lpthread `${pythonpath} --ldflags`"
	fi
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
#XS_ARG_DEFAULT(suidcgi, DUMMY, no, [install CGI scripts with setuid root privs])
AM_CONDITIONAL([SUIDCGI], [test x${enable_suidcgi} = xyes])

XS_ARG_DEFAULT(warnings, DUMMY, no, [enable extra compiler warnings])
# -Wformat-pre-promo is not standard
if test x${enable_warnings} = xyes
then
	CFLAGS="${CFLAGS} -g -ggdb -O3 -fsigned-char -fshort-enums -funroll-loops -std=c99 -pedantic -trigraphs -pipe -Wall -W -Wpointer-arith -Wshadow -Wbad-function-cast -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Wformat -Wformat-security -Wcomment -Wchar-subscripts -Wcast-align -Waggregate-return -Wnested-externs -Winline -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wpadded -Wunreachable-code"
fi

XS_ARG_DEFAULT(ssp, DUMMY, no, [enable stack smaching protector])
if test x${enable_ssp} = xyes
then
	AC_MSG_CHECKING([whether ${CC} supports stack protection...])
	TCFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} -fstack-protector-all -Wstack-protector"
	AC_COMPILE_IFELSE(AC_LANG_SOURCE([int i = 0;]),
		AC_MSG_RESULT([yes]),
		AC_MSG_RESULT([no])
		CFLAGS="${TCFLAGS}")
fi

dnl Test runs for required global variables.
AC_CHECK_DECLS([sys_errlist, optarg, environ])

dnl Generate configure output.
AC_SUBST(libxs_ldflags)
AC_SUBST(libxs_cflags)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_SUBST(SERVER_IDENT)
AC_CONFIG_FILES([Makefile config/Makefile contrib/Makefile fonts/Makefile icons/Makefile man/Makefile libcompat/Makefile src/Makefile man/httpd.1])
AC_OUTPUT
