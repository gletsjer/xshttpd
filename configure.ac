dnl Process this file with autoconf to produce a configure script.
AC_INIT(src/httpd.c)
AM_INIT_AUTOMAKE(xshttpd, 32b10)
AC_DEFINE_UNQUOTED(SERVER_IDENT, "xs-httpd/3.2 beta/0.10")
AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PATH_PROG(ppmtogif, ppmtogif, /bin/true)
AC_DEFINE_UNQUOTED(PATH_PPMTOGIF, "$ppmtogif")

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(alloca.h crypt.h err.h sys/exec.h getopt.h fcntl.h memory.h sys/mman.h sys/param.h sys/pstat.h sys/resource.h sys/select.h string.h strings.h sys/syslimits.h sys/sysmips.h sys/sysnews.h time.h sys/time.h unistd.h vfork.h vm/vm.h vm/pmap.h machine/vmparam.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_MMAP
AC_FUNC_SETPGRP
dnl AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS(gethostname mktime select strerror strstr strcasestr)

dnl SEPERATOR
AC_CHECK_FUNCS(bcopy bzero getaddrinfo getnameinfo killpg mkstemp mmap setenv seteuid setegid setresuid setresgid setrlimit setsid setpriority sigemptyset tempnam vfork)

dnl Prog specific checks
if test x$prefix = xNONE
then
	prefix=/usr/local
fi
AC_ARG_WITH(rootdir,
	[  --with-rootdir=PATH     directory to install data files [LIBDIR/httpd]],
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
AC_REPLACE_FUNCS(setgroups strptime snprintf)

AC_MSG_CHECKING(if you want SSL support)
AC_ARG_WITH(ssl,
	[  --with-ssl              crypto support],
	AC_MSG_RESULT($with_ssl)
	 AC_CHECK_LIB(crypto, SSLeay_version,
	  AC_CHECK_LIB(ssl, SSL_version,
       httpd_ldflags="${httpd_ldflags} -lcrypto -lssl"
	   httpd_cflags="${httpd_cflags} -I/usr/local/include -I/usr/local/ssl/include"
	   AC_DEFINE(HANDLE_SSL), AC_MSG_ERROR(SSL support requires libssl),
	    -lcrypto), AC_MSG_ERROR(SSL support requires libcrypto)),
	AC_MSG_RESULT(no))

AC_SHOW_HELP(--disable options (enabled by default):)
AC_ARG_DEFAULT(ssi, WANT_SSI, yes,
	[  --disable-ssi           disable server-side includes])
AC_ARG_DEFAULT(ipv6, INET6, yes,
	[  --disable-ipv6          disable ipv6 support])
AC_ARG_DEFAULT(script, HANDLE_SCRIPT, yes,
	[  --disable-script        disable scripting support (PHP)])
AC_ARG_DEFAULT(compress, HANDLE_COMPRESSED, yes,
	[  --disable-compress      disable auto-extraction of compressed files])
if test x${ac_cv_func_setrlimit} = xyes
then
	AC_ARG_DEFAULT(setrlimit, USE_SETRLIMIT, yes,
		[  --disable-setrlimit     disable resource limits for CGI scripts])
fi
AC_SHOW_HELP(--enable options (disabled by default):)
AC_ARG_DEFAULT(perl, HANDLE_PERL, no,
	[  --enable-perl           enable persistent perl interpreter])
AC_ARG_DEFAULT(warnings, , no,
	[  --enable-warnings       show extra compiler warnings])

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
if test x${ac_cv_func_setpriority} = xyes
then
	AC_NEED_CONST2(PRIO_MAX, NEED_PRIO_MAX, sys/time.h, sys/resource.h)
fi
dnl AC_EGREP_HEADER(sys_errlist, stdio.h,, AC_DEFINE(NEED_SYS_ERRLIST_DECL))
dnl AC_EGREP_HEADER(optarg, getopt.h,, AC_DEFINE(NEED_OPTARG_AND_OPTIND))
dnl AC_EGREP_HEADER(eniviron, unistd.h,, AC_DEFINE(NEED_DECL_ENVIRON))

AC_DEFINE_UNQUOTED(HTTPD_ROOT, "$rootdir")
AC_SUBST(miscdir)
AC_SUBST(cgidir)
AC_SUBST(fontdir)
AC_SUBST(icondir)
AC_SUBST(docdir)
AC_SUBST(logdir)

AC_MSG_CHECKING(for local domain)
hostname=`( hostname || cat /etc/HOSTNAME ) 2> /dev/null`
if test x$hostname = x -o x$hostname = x${hostname#*.}
then
	domain=".stack.nl"
else
	domain=".${hostname#*.}"
fi
AC_DEFINE_UNQUOTED(THISDOMAIN, "$domain")
AC_MSG_RESULT($domain)

AC_SUBST(LIBOBJS)
AC_SUBST(ldcrypt)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_OUTPUT([Makefile fonts/Makefile icons/Makefile man/Makefile
	misc/Makefile src/Makefile])
