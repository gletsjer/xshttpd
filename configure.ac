dnl Process this file with autoconf to produce a configure script.
AC_INIT
AC_CONFIG_SRCDIR([src/httpd.c])
AM_INIT_AUTOMAKE(xshttpd, 33b28)
AC_DEFINE_UNQUOTED(SERVER_IDENT, "xs-httpd/3.3 beta/0.28", [Server version])
AC_CONFIG_HEADERS([config.h])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_LN_S
AC_PATH_PROG(ppmtogif, ppmtogif, /bin/true)
AC_DEFINE_UNQUOTED(PATH_PPMTOGIF, "$ppmtogif",
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

AC_CHECK_HEADERS(alloca.h crypt.h err.h sys/exec.h getopt.h fcntl.h memory.h pcre.h pcre/pcre.h sys/mman.h sys/param.h sys/pstat.h sys/resource.h sys/select.h sys/syslimits.h sys/sysmips.h sys/sysnews.h sys/time.h time.h vfork.h vm/vm.h vm/pmap.h machine/vmparam.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_CHECK_TYPES(socklen_t,,, [#include <sys/types.h>
#include <sys/socket.h>])

dnl Checks for library functions.
AC_FUNC_MMAP
AC_FUNC_SETPGRP
dnl AC_FUNC_SETVBUF_REVERSED
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS(gethostname mktime select strcasestr strerror strlcat strlcpy strpbrk strstr)

dnl SEPERATOR
AC_CHECK_FUNCS(bcopy bzero getaddrinfo getnameinfo killpg mkstemp mmap sendfile seteuid setegid setresuid setresgid setrlimit setsid setpriority sigemptyset tempnam vfork setproctitle)

dnl Prog specific checks
if test x$prefix = xNONE
then
	prefix=/usr/local
fi
AC_ARG_WITH(rootdir,
	AS_HELP_STRING(--with-rootdir=PATH,directory to install data files (LIBDIR/httpd)),
	rootdir=${withval},
	rootdir=${prefix}/lib/httpd)
configdir=${rootdir}
XS_ARG_DIR(cgidir, cgi-bin)
XS_ARG_DIR(contribdir, contrib)
XS_ARG_DIR(fontdir, gfxcount)
XS_ARG_DIR(icondir, icons)
XS_ARG_DIR(docdir, htdocs)
XS_ARG_DIR(logdir, logs)

XS_FUNC_IN_LIB(crypt, HAVE_CRYPT, crypt, libxs)
XS_FUNC_IN_LIB(socket, HAVE_SOCKET, socket, httpd)
XS_FUNC_IN_LIB(MD5Init, HAVE_MD5, md, httpd)
AM_CONDITIONAL([MD5], [test x$ac_cv_lib_md_MD5Init = xyes])
AC_REPLACE_FUNCS(err setenv setgroups strlcat strlcpy strptime strsep snprintf)

XS_CHECK_WITH(pcre, PCRE support, no)
if test x${with_pcre} = xyes
then
	XS_FUNC_IN_LIB(pcre_exec, HAVE_PCRE, pcre, httpd)
	AM_CONDITIONAL([PCRE], [test x$ac_cv_lib_pcre_pcre_exec = xyes])
else
	AM_CONDITIONAL([PCRE], false)
fi

XS_CHECK_WITH(ldap, LDAP authentication support, no)
if test x${with_ldap} = xyes
then
	XS_FUNC_IN_LIB(ldap_initialize, AUTH_LDAP, ldap, httpd)
	AM_CONDITIONAL([LDAP], [test x$ac_cv_lib_ldap_ldap_initialize = xyes])
else
	AM_CONDITIONAL([LDAP], false)
fi

XS_CHECK_WITH(ssl, SSL crypto support, yes)
if test x${with_ssl} = xyes
then
	XS_FUNC_IN_LIB(SSLeay_version, HAVE_SSLEAY, crypto, httpd)
	XS_FUNC_IN_LIB(SSL_version, HAVE_SSL, ssl, httpd, -lcrypto)
	if test x${ac_cv_lib_ssl_SSL_version} = xyes
	then
		httpd_cflags="${httpd_cflags} -I/usr/local/ssl/include"
		AC_DEFINE(HANDLE_SSL,,
			[Enable SSL support, you must have UseSSL in your config to enable this])
		AC_DEFINE(CERT_FILE, "cert.pem",
			[File containing public SSL certificate])
		AC_DEFINE(KEY_FILE, "key.pem",
			[File containing private SSL server key])
	else
		AC_MSG_ERROR([Cannot find libraries for --with-ssl])
	fi
fi

# XS_SHOW_HELP([--enable options], [default in brackets:])
XS_ARG_DEFAULT(ssi, WANT_SSI, yes,
	[enable server-side includes])
XS_ARG_DEFAULT(ipv6, INET6, yes,
	[enable ipv6 support])
# This is now enabled by default
AC_DEFINE(SCRIPT_METHODS, "script.methods",
	[File describing script extensions and interpreters])
# This is now enabled by default
AC_DEFINE(COMPRESS_METHODS, "compress.methods",
	[File describing compression extensions and programs])
# XS_SHOW_HELP([--enable options], [disabled by default:])
XS_ARG_DEFAULT(perl, HANDLE_PERL, no,
	[enable persistent perl interpreter])
XS_ARG_DEFAULT(warnings, DUMMY, no,
	[enable extra compiler warnings])

# -Wformat-pre-promo is not standard
if test x${enable_warnings} = xyes
then
	CFLAGS="${CFLAGS} -g -O -fsigned-char -fshort-enums -funroll-loops -finline-functions -fexpensive-optimizations -pedantic -ansi -trigraphs -Wall -W -Wimplicit -Wpointer-arith -Wshadow -pipe -Wbad-function-cast -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Wreturn-type -Wformat -Wformat=2 -Wtrigraphs -Wswitch -Wcomment -Wchar-subscripts -Wuninitialized -Wparentheses -Wcast-align -Waggregate-return -Wnested-externs -Winline"
else
	CFLAGS="${CFLAGS} -g"
fi

if test x${enable_perl} = xyes
then
	if test x${enable_script} = xno
	then
		echo "You can only use --enable-perl with --enable-script"
		exit 1
	fi
	httpd_cflags="${httpd_cflags} `perl -MExtUtils::Embed -e ccopts`"
	httpd_ldflags="${httpd_ldflags} `perl -MExtUtils::Embed -e ldopts`"
fi

dnl Test runs for required global variables

AC_CHECK_DECLS([sys_errlist, optarg, environ])

AC_DEFINE_UNQUOTED(HTTPD_ROOT, "$rootdir",
	[Default root directory for the server. This is were the subdirs /logs, /htdocs and /cgi-bin reside. This can be overriden from RootDir config.])
AC_SUBST(configdir)
AC_SUBST(contribdir)
AC_SUBST(cgidir)
AC_SUBST(fontdir)
AC_SUBST(icondir)
AC_SUBST(docdir)
AC_SUBST(logdir)

AC_MSG_CHECKING(for local domain)
hostname=` ( hostname || cat /etc/HOSTNAME ) 2> /dev/null `
if test x$hostname = x -o x$hostname = x${hostname#*.}
then
	domain=".stack.nl"
else
	domain=".${hostname#*.}"
fi
AC_MSG_RESULT($domain)
AC_DEFINE_UNQUOTED(THISDOMAIN, "$domain",
	[The name of your domain, including leading dot. This is used to strip out referrers from your own site.])

AC_SUBST(libxs_ldflags)
AC_SUBST(libxs_cflags)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_CONFIG_FILES([Makefile config/Makefile contrib/Makefile fonts/Makefile icons/Makefile man/Makefile src/Makefile])
AC_OUTPUT
