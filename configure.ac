dnl Process this file with autoconf to produce a configure script.
AC_INIT(src/httpd.c)
AM_INIT_AUTOMAKE(xshttpd, 30b07)
AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(alloca.h crypt.h err.h sys/exec.h fcntl.h memory.h sys/mman.h sys/param.h sys/pstat.h sys/resource.h sys/select.h string.h strings.h sys/syslimits.h sys/sysmips.h sys/sysnews.h time.h sys/time.h unistd.h vfork.h vm/vm.h machine/vmparam.h)

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
AC_CHECK_FUNCS(gethostname mktime select strerror strstr)

dnl SEPERATOR
AC_CHECK_FUNCS(bcopy bzero getaddrinfo getnameinfo killpg mkstemp mmap setenv seteuid setegid setresuid setresgid setsid setpriority sigemptyset tempnam vfork)

dnl Prog specific checks
AC_ARG_WITH(rootdir,
	[  --with-rootdir=PATH     directory to install data files [LIBDIR/httpd]],
	rootdir=${withval},
	rootdir=${libdir}/httpd)
miscdir=${rootdir}
miscdir=${libdir}/httpd
AC_ARG_DIR(cgidir, cgi-bin)
AC_ARG_DIR(fontdir, gfxcount)
AC_ARG_DIR(icondir, icons)
AC_ARG_DIR(docdir, htdocs)
AC_ARG_DIR(logdir, logs)

AC_CHECK_FUNCS(crypt,,
	AC_CHECK_LIB(crypt, crypt, ldcrypt="-lcrypt"))
AC_CHECK_FUNCS(socket,,
	AC_CHECK_LIB(socket, socket, httpd_ldflags="${httpd_ldflags} -lsocket"))
AC_MSG_CHECKING(if you want SSL support)
AC_ARG_WITH(ssl,
	[  --with-ssl              crypto support],
	AC_MSG_RESULT($with_ssl)
	 AC_CHECK_LIB(crypto, main,
	  AC_CHECK_LIB(ssl, main,
       httpd_ldflags="${httpd_ldflags} -lcrypto -lssl"
	   httpd_cflags="${httpd_cflags} -I/usr/local/include -I/usr/local/ssl/include"
	   AC_DEFINE(HANDLE_SSL),,
	    -lcrypto)),
	AC_MSG_RESULT(no))
AC_ARG_DEFAULT(ssi, WANT_SSI,
	[  --disable-ssi           disable server-side includes])
AC_ARG_DEFAULT(ipv6, INET6,
	[  --disable-ipv6          disable ipv6 support])
AC_ARG_DEFAULT(virtual, SIMPLE_VIRTUAL_HOSTING,
	[  --disable-virtual       disable simple virtual hosting])
AC_ARG_DEFAULT(restrict, RESTRICTXS,
	[  --disable-restrict      disable restricted .noxs access])
AC_ARG_DEFAULT(script, HANDLE_SCRIPT,
	[  --disable-script        disable scripting support (PHP)])
AC_ARG_DEFAULT(compress, HANDLE_COMPRESSED,
	[  --disable-compress      disable auto-extraction of compressed files])
AC_ARG_DEFAULT(setrlimit, USE_SETRLIMIT,
	[  --disable-setrlimit     disable resource limits for CGI scripts])

dnl Test runs for required global variables

AC_NEED_CONST(sys_errlist, NEED_SYS_ERRLIST_DECL, stdio.h)
AC_NEED_CONST(optarg, NEED_OPTARG_AND_OPTIND, unistd.h)
AC_NEED_CONST(environ, NEED_DECL_ENVIRON, unistd.h)
if test "${ac_cv_func_setpriority}" = yes
then
	AC_NEED_CONST2(PRIO_MAX, NEED_PRIO_MAX, sys/time.h, sys/resource.h)
fi
dnl AC_EGREP_HEADER(sys_errlist, stdio.h,, AC_DEFINE(NEED_SYS_ERRLIST_DECL))
dnl AC_EGREP_HEADER(optarg, getopt.h,, AC_DEFINE(NEED_OPTARG_AND_OPTIND))
dnl AC_EGREP_HEADER(eniviron, unistd.h,, AC_DEFINE(NEED_DECL_ENVIRON))

AC_SUBST(miscdir)
AC_SUBST(cgidir)
AC_SUBST(fontdir)
AC_SUBST(icondir)
AC_SUBST(docdir)
AC_SUBST(logdir)

dnl I just get tired of typing this
dnl Should be replaced by a decent check some day...
test -f /etc/HOSTNAME && \
	grep vwww /etc/HOSTNAME && \
	AC_DEFINE(BROKEN_GETNAMEINFO)

CFLAGS=-g
AC_SUBST(ldcrypt)
AC_SUBST(httpd_ldflags)
AC_SUBST(httpd_cflags)
AC_OUTPUT([Makefile fonts/Makefile icons/Makefile man/Makefile
	misc/Makefile src/Makefile])
