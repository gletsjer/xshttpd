dnl Process this file with autoconf to produce a configure script.
AC_INIT(src/httpd.c)
AM_INIT_AUTOMAKE(xshttpd, 33b13)
AC_DEFINE_UNQUOTED(SERVER_IDENT, "xs-httpd/3.3 beta/0.13", [Server version])
AM_CONFIG_HEADER(config.h)

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

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(alloca.h crypt.h err.h sys/exec.h getopt.h fcntl.h memory.h sys/mman.h sys/param.h sys/pstat.h sys/resource.h sys/select.h string.h strings.h sys/syslimits.h sys/sysmips.h sys/sysnews.h time.h sys/time.h unistd.h vfork.h vm/vm.h vm/pmap.h machine/vmparam.h)

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
AC_CHECK_FUNCS(gethostname mktime select strcasestr strerror strpbrk strstr)

dnl SEPERATOR
AC_CHECK_FUNCS(bcopy bzero getaddrinfo getnameinfo killpg mkstemp mmap sendfile seteuid setegid setresuid setresgid setrlimit setsid setpriority sigemptyset tempnam vfork setproctitle)

dnl Prog specific checks
if test x$prefix = xNONE
then
	prefix=/usr/local
fi
AC_ARG_WITH(rootdir,
	AC_HELP_STRING([--with-rootdir=PATH],
		[directory to install data files (LIBDIR/httpd)]),
	rootdir=${withval},
	rootdir=${prefix}/lib/httpd)
miscdir=${rootdir}
AC_ARG_DIR(cgidir, cgi-bin)
AC_ARG_DIR(fontdir, gfxcount)
AC_ARG_DIR(icondir, icons)
AC_ARG_DIR(docdir, htdocs)
AC_ARG_DIR(logdir, logs)

AC_CHECK_FUNCS(crypt,,
	AC_CHECK_LIB(crypt, crypt, AC_DEFINE(HAVE_CRYPT) ldcrypt="-lcrypt"))
AC_CHECK_FUNCS(socket,,
	AC_CHECK_LIB(socket, socket, httpd_ldflags="${httpd_ldflags} -lsocket"))
AC_CHECK_FUNCS(MD5Init,,
	AC_CHECK_LIB(md, MD5Init, httpd_ldflags="${httpd_ldflags} -lmd"))
AM_CONDITIONAL([MD5], [test x$ac_cv_lib_md_MD5Init = xyes])
AC_REPLACE_FUNCS(err setenv setgroups strptime strsep snprintf)

AC_MSG_CHECKING(if you want SSL support)
AC_ARG_WITH(ssl,
	AC_HELP_STRING([--with-ssl], [crypto support (yes)]),
	AC_MSG_RESULT($with_ssl),
	with_ssl=yes
	AC_MSG_RESULT(yes))

if test x${with_ssl} = xyes
then
	AC_CHECK_LIB(crypto, SSLeay_version,
		ac_cv_lib_crypto=yes,
		AC_MSG_ERROR(SSL support requires libcrypto))
	if test x${ac_cv_lib_crypto} = xyes
	then
	AC_CHECK_LIB(ssl, SSL_version,
		ac_cv_lib_ssl=yes,
		AC_MSG_ERROR(SSL support requires libssl),
		-lcrypto)
	fi
	if test x${ac_cv_lib_ssl} = xyes
	then
		httpd_ldflags="${httpd_ldflags} -lcrypto -lssl"
		httpd_cflags="${httpd_cflags} -I/usr/local/include -I/usr/local/ssl/include"
		AC_DEFINE(HANDLE_SSL,,
			[Enable SSL support, you must have UseSSL in your config to enable this])
		AC_DEFINE(CERT_FILE, "cert.pem",
			[File containing public SSL certificate])
		AC_DEFINE(KEY_FILE, "key.pem",
			[File containing private SSL server key])
	fi
fi

# AC_SHOW_HELP([--enable options], [default in brackets:])
AC_ARG_DEFAULT(ssi, WANT_SSI, yes,
	[enable server-side includes])
AC_ARG_DEFAULT(ipv6, INET6, yes,
	[enable ipv6 support])
# This is now enabled by default
AC_DEFINE(SCRIPT_METHODS, "script.methods",
	[File describing script extensions and interpreters])
# This is now enabled by default
AC_DEFINE(COMPRESS_METHODS, "compress.methods",
	[File describing compression extensions and programs])
# AC_SHOW_HELP([--enable options], [disabled by default:])
AC_ARG_DEFAULT(perl, HANDLE_PERL, no,
	[enable persistent perl interpreter])
AC_ARG_DEFAULT(warnings, DUMMY, no,
	[enable extra compiler warnings])

if test x${enable_warnings} = xyes
then
	CFLAGS="-g -O -fsigned-char -pedantic -ansi -trigraphs -Wall -W -Wpointer-arith -Wshadow -pipe -Wbad-function-cast -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Wreturn-type -Wformat -Wswitch -Wcomment -Wchar-subscripts -Wuninitialized -Wparentheses -Wcast-align -Waggregate-return -Wnested-externs -Winline"
else
	CFLAGS="-g"
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

AC_NEED_CONST(sys_errlist, NEED_SYS_ERRLIST_DECL, stdio.h)
AC_NEED_CONST(optarg, NEED_OPTARG_AND_OPTIND, unistd.h)
AC_NEED_CONST(environ, NEED_DECL_ENVIRON, unistd.h)

dnl AC_EGREP_HEADER(sys_errlist, stdio.h,, AC_DEFINE(NEED_SYS_ERRLIST_DECL))
dnl AC_EGREP_HEADER(optarg, getopt.h,, AC_DEFINE(NEED_OPTARG_AND_OPTIND))
dnl AC_EGREP_HEADER(eniviron, unistd.h,, AC_DEFINE(NEED_DECL_ENVIRON))

AC_DEFINE_UNQUOTED(HTTPD_ROOT, "$rootdir",
	[Default root directory for the server. This is were the subdirs /logs, /htdocs and /cgi-bin reside. This can be overriden from RootDir config.])
AC_SUBST(miscdir)
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

AC_SUBST(ldcrypt)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_OUTPUT([Makefile fonts/Makefile icons/Makefile man/Makefile misc/Makefile src/Makefile])
