/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
  
/* You can edit this file by hand, but that is usually not necessary.
Supplied with this package is a program called `autodetect', which,
when run, will determine most of the values that are needed here.
The autodetect program can be started by typing `sh autodetect' on
a shell prompt. */
  

/* Do you want to enable server side includes? Server side includes
allow users to include files from within a file, have access to a
visitor counter, and display all kinds of nice things. See README.html
for more information about these SSI's. */
  
#define WANT_SSI 

/* IPv6 support. Define this if your machine understands IPv6 internet
 * sockets and you want the httpd to listen to these as well. */

#define INET6

/* SSL support. This requires the OpenSSL library.
 * To use https, start an extra deamon with the '-s' option. */
/* You can enable this when compiling httpd, but should disable it
 * for all the other utils. Yes, that's a hack, yes it needs fixing. */

#undef HANDLE_SSL
#define CERT_FILE	"cert.pem"
#define KEY_FILE	"key.pem"

/* Simple virtual hosting: when receiving requests for a virtual hostname,
 * the server will try to access files from the HTTPD_ROOT/hostname/
 * directory instead of HTTPD_DOCUMENT_ROOT. This doesn't effect the
 * location for user www directories (you can tune local.c for that). */

#define SIMPLE_VIRTUAL_HOSTING

/* Define this if you want to allow certain hosts to read a directory even
 * if it contains a .noxs file. You can list the IP numbers of the host
 * that should have access in the .noxs file (no hostnames). You may list
 * only the start of an IP number to allow a range of hostnames.
 * E.g. if .noxs contains 192.168.1, access will be granted to
 * 192.168.1.0 - 192.168.1.255 and denied to the rest of the world. */

#define RESTRICTXS
 
/* Generic file interpretation support (read: PHP)
 * This extension allows files with certain extensions to be parsed
 * by an external interpreter. You will have to specify the extensions
 * and programs in SCRIPT_METHODS
 */
#define HANDLE_SCRIPT
#define SCRIPT_METHODS "script.methods"

/* Define these if you have the respective include file. For example,
define HAVE_SYS_SYSLIMITS_H if your system has the sys/syslimits.h
include file. Include files can usually be found in the /usr/include
directory on your system. You can leave them all defined and then
try to make the programs: your compiler will list the ones it CAN'T
find, which you can then then undefine here. If you don't have
"strings.h", the httpd will use "string.h" instead. */
  
#define HAVE_STRING_H 
#define HAVE_STRINGS_H
#define HAVE_SYS_WAIT_H 
#define HAVE_SYS_SELECT_H 
#define HAVE_SYS_PARAM_H 
#define HAVE_SYS_SYSLIMITS_H 
#define HAVE_SYS_EXEC_H 
#undef HAVE_SYS_PSTAT_H 
#undef HAVE_SYS_SYSMIPS_H 
#undef HAVE_SYS_SYSNEWS_H 
#define HAVE_VM_VM_H 
#define HAVE_MACHINE_VMPARAM_H 
#define HAVE_ERR_H 
#undef HAVE_GETOPT_H 
#define HAVE_TIME_H 
#define HAVE_SYS_TIME_H 
#undef HAVE_VFORK_H 
#define HAVE_MEMORY_H 
#undef HAVE_CRYPT_H 
#define HAVE_SYS_MMAN_H 
#define HAVE_SYS_RESOURCE_H 
  
/* Do we want to use setrlimit() to limit CGI programs in what they do? */
  
#define DONT_USE_SETRLIMIT 
  
/* Define SYS_TIME_WITH_TIME if your system allows including both
/sys/time.h and time.h. If your system does not allow it, undefine
SYS_TIME_WITH_TIME. */ 
  
#define SYS_TIME_WITH_TIME
  
/* The path in which `ppmtogif' (part of the NetPBM package) can be found.
If you do not have this, the graphical counter will not work (I'm
working on this...). In that case, #undef this line. */
  
#define PATH_PPMTOGIF "/usr/local/bin/ppmtogif"
  
/* The default root directory for the server. This is where the subdirs
'logs', 'htdocs' and 'cgi-bin' go. This is used as a base directory
for other directories (see below). It can be overridden from the
command line. */
  
#define HTTPD_ROOT "/usr/local/lib/httpd"
  
/* The default number of servers. This is the maximum number of requests
that the server will be able to handle concurrently. Watch out though:
it also forks this number of processes (once only). You can change this
number from the command line if you wish. */
  
#define HTTPD_NUMBER 20
  
/* The default group and user ID of the WWW server. It assumes this group
and user ID when a page or cgi-binary is requested that is not in a
user's home directory. Typically this would be 'nobody' and 'nogroup',
but you can also make a seperate user and group id, for example 'http'
and 'www'. You can change these defaults from the command line if you
wish. */ 
  
#define HTTPD_USERID "nobody"
#define HTTPD_GROUPID "nogroup"
  
/* You can change this define if you do not want the starting place of
the WWW server's virtual / to be in the htdocs directory. The path
can begin with a slash, in which case it is assumed to be an
absolute path. If it does not start with a slash, it is assumed
to be relative to HTTPD_ROOT. */
  
#define HTTPD_DOCUMENT_ROOT "htdocs"
  
/* You can change the name of the directory that contains CGI binaries.
When the server encounters requests for either /cgi-bin/something or
/~USER/cgi-bin/something, it is assumed that that program has to be run
to get the requested output. You can change the name of cgi-bin. */
  
#define HTTPD_SCRIPT_ROOT "cgi-bin"
  
/* You can change this define if you do not want the starting place of
the WWW server's real cgi-bin directory to be in the server root.
This is the "physical" name of the cgi-bin directory in the virtual /.
Again, the path can be relative to HTTPD_ROOT or it can be an
absolute path. See above (HTTPD_DOCUMENT_ROOT). */
  
#define HTTPD_SCRIPT_ROOT_P "cgi-bin"
  
/* This path defines where the HTTP deamon will store its log files.
You can either specify a relative path or an absolute path
(see above, at HTTPD_DOCUMENT_ROOT). Overridable on the command
line. */ 
  
#define HTTPD_LOG_ROOT "logs"
  
/* This path defines where the counter file is located. */
  
#define CNT_DATA "logs/xs-counter.data"
#define CNT_LOCK "logs/xs-counter.lock"
  
/* This path defines where the PID file is located. Again, you can specify
a relative or an absolute path. */
  
#define PID_PATH "/var/run/httpd.pid"
  
/* Fill in the name of your domain here, including the leading dot.
This is used to strip out refers that come from your own site
(which are usually not interesting). If you want all refers,
undefine THISDOMAIN. This can be overridden on the command line. */
  
#define THISDOMAIN ".stack.nl"
  
/* The name of the default WWW page if a directory is specified.
Both these names are checked. */
  
#define INDEX_HTML "index.html"
#define INDEX_HTML_2 "index.htm"
  
/* The name of the mime.types file which the server uses to determine
the content-type of the file that it is going to send. Again,
this path can be relative to HTTPD_ROOT or it can be an absolute
path (see above at HTTPD_DOCUMENT_ROOT). BEWARE! The contents of the
mime.types file are NOT standard. Read the comments in the default
mime.types for details. */
  
#define MIMETYPESFILE "mime.types"
  
/* The server can automatically uncompress compressed files on the server
side if the other side is not able to handle the compression method.
If you want to turn on this feature, define HANDLE_COMPRESSED. See the
default compress.methods for more details. */
  
#define HANDLE_COMPRESSED 
#define COMPRESS_METHODS "compress.methods"
 
/* What is the bit bucket on your system? */
  
#define BITBUCKETNAME "/dev/null"
  
/* Where can the WWW server place some temporary files? The only
temporary files at this moment at generated by the automatic
uncompressor. Temporary files are removed as soon as they are
opened, so there is no chance of any of them staying behind.
Note that this directory must be writable for everybody. */
  
#define TEMPORARYPATH "/tmp"

/* Does your system support the setpriority() library/system call? If not,
the WWW server will not be able te set its priority to a lower setting. */
  
#define HAVE_SETPRIORITY 
  
/* Does your system support the vfork() system call? If not, fork()
will be used instead. vfork() should be more efficient than fork(). */
  
#define HAVE_VFORK 
  
/* Does your system support the mmap() system call? If not, the httpd
will run slower when sending non-HTML files, because it will have to
use a read()/write() loop instead of one mmap()/write(). */
  
#define HAVE_MMAP 
  
/* Does your system support the tempnam() library call? If not, the
httpd will generate a random file name itself, but it is not
guaranteed to be unique, with all the consequences. */
  
#define HAVE_TEMPNAM 
  
/* Does your system have the bcopy() library call? If not, then the
programs will use memcopy() instead. */
  
#define HAVE_BCOPY 
  
/* Does your system have the bzero() library call? If not, then the
programs will use memset() instead. */
  
#define HAVE_BZERO 
  
/* Does your system have the setsid() library call? If not, then the
programs will use setpgrp() instead. */
  
#define HAVE_SETSID 
  
/* Does your system have the setenv(), unsetenv() and getenv() library calls?
If not, then the programs will use their own version. */
  
#define HAVE_SETENV 
  
/* Does your system have the seteuid() and setegid() system/library calls?
If not, then the programs will use setreuid() and setregid() instead. */
  
#define HAVE_SETEUID 
#define HAVE_SETEGID 
  
/* Does your system have the setresuid() en setresgid() system/library calls?
These are only needed if you do not have seteuid()/setegid() and
setreuid()/setreuid(). */ 
  
#undef HAVE_SETRESUID 
#undef HAVE_SETRESGID 
  
/* Does your system have the strerror() library call? If not, then the
programs will use their own version. If you need to declare sys_errlist
and sys_nerr in the program itself, define NEED_SYS_ERRLIST_DECL also. */
  
#define HAVE_STRERROR 
#undef NEED_SYS_ERRLIST_DECL 
  
/* Does your system declare optarg and optind by itself? If not, the
programs will declare it themselves. If you need the programs to
declare the symbols by themselves, #define NEED_OPTARG_AND_OPTIND. */
  
#undef NEED_OPTARG_AND_OPTIND 
  
/* Does your system declare environ by itself? If not, the prorgams will
declare it themselves. If you need the programs to declare the symbols,
then #define NEED_DECL_ENVIRON. */
  
#define NEED_DECL_ENVIRON 
  
/* Does your system have the killpg() call? If so, then define HAVE_KILLPG.
A version of killpg() will be created in extra.c otherwise. */
  
#define HAVE_KILLPG 
  
/* Does your system have the sigemptyset() library call? If so, it will
be used, otherwise sa_mask will just be assigned 0. */
  
#define HAVE_SIGEMPTYSET 
  
/* Does your system have a good working getnameinfo() library call? If so,
it will be used, otherwise getaddrinfo() is used instead. */
  
#define HAVE_GETNAMEINFO
  
/* Does your system have the seteuid() and setegid() system/library calls?
If not, then the programs will use setreuid() and setregid() instead. */
  
#define HAVE_SETEUID 
#define HAVE_SETEGID 
  
/* Does your system have the setresuid() en setresgid() system/library calls?
These are only needed if you do not have seteuid()/setegid() and
setreuid()/setreuid(). */ 
  
#undef HAVE_SETRESUID 
#undef HAVE_SETRESGID 
  
/* Does your system have the strerror() library call? If not, then the
programs will use their own version. If you need to declare sys_errlist
and sys_nerr in the program itself, define NEED_SYS_ERRLIST_DECL also. */
  
#define HAVE_STRERROR 
#undef NEED_SYS_ERRLIST_DECL 
  
/* Does your system declare optarg and optind by itself? If not, the
programs will declare it themselves. If you need the programs to
declare the symbols by themselves, #define NEED_OPTARG_AND_OPTIND. */
  
#undef NEED_OPTARG_AND_OPTIND 
  
/* Does your system declare environ by itself? If not, the prorgams will
declare it themselves. If you need the programs to declare the symbols,
then #define NEED_DECL_ENVIRON. */
  
#define NEED_DECL_ENVIRON 
  
/* Does your system have the killpg() call? If so, then define HAVE_KILLPG.
A version of killpg() will be created in extra.c otherwise. */
  
#define HAVE_KILLPG 
  
/* Does your system have the sigemptyset() library call? If so, it will
be used, otherwise sa_mask will just be assigned 0. */
  
#define HAVE_SIGEMPTYSET 
  
/* If your system has a VERY old setvbuf(), the second and third arguments
will have to be reversed (SysV versions earlier than version 3). If you
have this very old style setvbuf(), define SETVBUF_REVERSED. */
  
#undef SETVBUF_REVERSED 
  
/* Does your system know about the type "pid_t"? If not, then define
NOPID_T instead of undefining it. */
  
#undef NOPID_T 
  
/* Does your system know about the type "size_t"? If not, then define
NOSIZE_T instead of undefining it. */
  
#undef NOSIZE_T 
  
/* Does your system know about the type "uid_t"? If not, then define
NOUID_T instead of undefining it. */
  
#undef NOUID_T 
  
/* Does your system know about the type "gid_t"? If not, then define
NOGID_T instead of undefining it. */
  
#undef NOGID_T 
  
/* The default PATH environment variable that CGI binaries are started
with. This is so users' binaries can find the programs that they
depend on. The path must be given in the normal /bin/sh format. */
  
#define SCRIPT_PATH "/usr/bin:/bin:/usr/local/bin"
  
/* The name of the access authority file */
  
#define AUTHFILE ".xsauth"
  
/* Argument to listen(). Leave it as it is, it should be fine. */
  
#define MAXLISTEN 50
  
/* If your C compiler does not understand prototypes, #define NOPROTOS
instead of undefining it. You have a really old C compiler if this
is the case. Consider upgrading to GCC, a fantastic C compiler
(free!) which runs on nearly every platform. */
  
#undef NOPROTOS 
  
/* If your C compiler does not even understand forwards, then #define
NOFORWARDS instead of undefining it. Your compiler is REALLY stupid
if it does not understand forwards. Read above about GCC! */
  
#undef NOFORWARDS 
  
/* If your compiler does not understand "new-style" declarations, then
#define NONEWSTYLE instead of undefining it. Read above about GCC! */
  
#undef NONEWSTYLE 
  
/* If your compiler does not understand the 'const' keyword, then
#define NOCONST instead of undefining it. Read above about GCC! */
  
#undef NOCONST 
  
/* If your compiler does not understand the 'static' keyword, then
#define NOSTATIC instead of undefining it. Read above about GCC! */
  
#undef NOSTATIC 
  
/* If your compiler does not understand the 'extern' keyword, then
#define NOEXTERN instead of undefining it. Read above about GCC! */
  
#undef NOEXTERN 
  
/* If your compiler does not understand the 'void' keyword, then
#define NOVOID instead of undefining it. Read above about GCC! */
  
#undef NOVOID 

/* Koresh hack */
  
/* If your system has a VERY old setvbuf(), the second and third arguments
will have to be reversed (SysV versions earlier than version 3). If you
have this very old style setvbuf(), define SETVBUF_REVERSED. */
  
#undef SETVBUF_REVERSED 
  
/* Does your system know about the type "pid_t"? If not, then define
NOPID_T instead of undefining it. */
  
#undef NOPID_T 
  
/* Does your system know about the type "size_t"? If not, then define
NOSIZE_T instead of undefining it. */
  
#undef NOSIZE_T 
  
/* Does your system know about the type "uid_t"? If not, then define
NOUID_T instead of undefining it. */
  
#undef NOUID_T 
  
/* Does your system know about the type "gid_t"? If not, then define
NOGID_T instead of undefining it. */
  
#undef NOGID_T 
  
/* The default PATH environment variable that CGI binaries are started
with. This is so users' binaries can find the programs that they
depend on. The path must be given in the normal /bin/sh format. */
  
#define SCRIPT_PATH "/usr/bin:/bin:/usr/local/bin"
  
/* The name of the access authority file */
  
#define AUTHFILE ".xsauth"
  
/* Argument to listen(). Leave it as it is, it should be fine. */
  
#define MAXLISTEN 50
  
/* If your C compiler does not understand prototypes, #define NOPROTOS
instead of undefining it. You have a really old C compiler if this
is the case. Consider upgrading to GCC, a fantastic C compiler
(free!) which runs on nearly every platform. */
  
#undef NOPROTOS 
  
/* If your C compiler does not even understand forwards, then #define
NOFORWARDS instead of undefining it. Your compiler is REALLY stupid
if it does not understand forwards. Read above about GCC! */
  
#undef NOFORWARDS 
  
/* If your compiler does not understand "new-style" declarations, then
#define NONEWSTYLE instead of undefining it. Read above about GCC! */
  
#undef NONEWSTYLE 
  
/* If your compiler does not understand the 'const' keyword, then
#define NOCONST instead of undefining it. Read above about GCC! */
  
#undef NOCONST 
  
/* If your compiler does not understand the 'static' keyword, then
#define NOSTATIC instead of undefining it. Read above about GCC! */
  
#undef NOSTATIC 
  
/* If your compiler does not understand the 'extern' keyword, then
#define NOEXTERN instead of undefining it. Read above about GCC! */
  
#undef NOEXTERN 
  
/* If your compiler does not understand the 'void' keyword, then
#define NOVOID instead of undefining it. Read above about GCC! */
  
#undef NOVOID 

/* Koresh hack */

#ifdef		__linux__
#define		_POSIX_SOURCE
#define		_BSD_SOURCE
#include	<features.h>
#include	<limits.h>
#include	<unistd.h>
#include	<getopt.h>
#include	<sys/types.h>
#include	<sys/time.h>
#undef		HAVE_SYS_SYSLIMITS_H
#undef		HAVE_SYS_EXEC_H 
#undef		HAVE_VM_VM_H 
#undef		HAVE_MACHINE_VMPARAM_H 
#endif		/* __linux__ */

/* Koresh hack ends here */
  
/* No user serviceable text after this line */

#ifndef		HAVE_VFORK
#define		vfork		fork
#endif		/* HAVE_VFORK */

#ifndef		NOPROTOS
#define		PROTO(a)	a
#else
#define		PROTO(a)	()
#endif

#ifndef		NONEWSTYLE
#define		DECL0			(void)
#define		DECL1(t1,v1)		(t1 v1)
#define		DECL2(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL3(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#define		DECL4(t1,v1,t2,v2,t3,v3,t4,v4) (t1 v1, t2 v2, t3 v3, t4 v4)
#ifdef		NOCONST
#define		DECL1C(t1,v1)		(t1 v1)
#define		DECL2C_(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL2_C(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL2CC(t1,v1,t2,v2)	(t1 v1, t2 v2)
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (t1 v1, t2 v2, t3 v3)
#else		/* Not NOCONST */
#define		DECL1C(t1,v1)		(const t1 v1)
#define		DECL2C_(t1,v1,t2,v2)	(const t1 v1, t2 v2)
#define		DECL2_C(t1,v1,t2,v2)	(t1 v1, const t2 v2)
#define		DECL2CC(t1,v1,t2,v2)	(const t1 v1, const t2 v2)
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (t1 v1, const t2 v2, t3 v3)
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (const t1 v1, const t2 v2, t3 v3)
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (const t1 v1, t2 v2, t3 v3)
#endif		/* NOCONST */
#else		/* Not not NONEWSTYLE */
#define		DECL0			()
#define		DECL1(t1,v1)		(v1) t1 v1;
#define		DECL2(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL3(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#define		DECL4(t1,v1,t2,v2,t3,v3,t4,v4) \
				(v1, v2, v3, v4) t1 v1; t2 v2; t3 v3; t4 v4;
#ifdef		NOCONST
#define		DECL1C(t1,v1)		(v1) t1 v1;
#define		DECL2C_(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL2CC(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL2_C(t1,v1,t2,v2)	(v1, v2) t1 v1; t2 v2;
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; t2 v2; t3 v3;
#else		/* Not NOCONST */
#define		DECL1C(t1,v1)		(v1) const t1 v1;
#define		DECL2C_(t1,v1,t2,v2)	(v1, v2) const t1 v1; t2 v2;
#define		DECL2CC(t1,v1,t2,v2)	(v1, v2) const t1 v1; const t2 v2;
#define		DECL2_C(t1,v1,t2,v2)	(v1, v2) t1 v1; const t2 v2;
#define		DECL3_C_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) t1 v1; const t2 v2; t3 v3;
#define		DECL3CC_(t1,v1,t2,v2,t3,v3) (v1, v2, v3) const t1 v1; const t2 v2; t3 v3;
#define		DECL3C__(t1,v1,t2,v2,t3,v3) (v1, v2, v3) const t1 v1; t2 v2; t3 v3;
#endif		/* NOCONST */
#endif		/* NONEWSTYLE */

#ifdef		NOCONST
#define		const
#endif		/* NOCONST */

#ifdef		NOSTATIC
#define		static
#endif		/* NOSTATIC */

#ifdef		NOEXTERN
#define		extern
#endif		/* NOEXTERN */

#ifdef		NOVOID
#define		VOID
#else		/* Not NOVOID */
#define		VOID		void
#endif		/* NOVOID */

#ifdef		NOPID_T
#define		pid_t		long
#endif		/* NOPID_T */

#ifdef		NOSIZE_T
#define		size_t		long
#endif		/* NOSIZE_T */

#ifdef		NOUID_T
#define		pid_t		int
#endif		/* NOUID_T */

#ifdef		NOGID_T
#define		gid_t		int
#endif		/* NOGID_T */

#define		XS_PATH_MAX	1024

#ifndef		HAVE_BCOPY
#define		bcopy(a,b,c)	memmove((b), (a), (c))
#endif		/* HAVE_MEMMOVE */

#ifndef		HAVE_BZERO
#define		bzero(a,b)	memset((a), 0, (b))
#endif		/* HAVE_BZERO */

#ifndef		HAVE_SETEUID
#ifdef		HAVE_SETRESUID
#define		seteuid(a)	setresuid(-1, (a), -1)
#else		/* Not HAVE_SETRESUID */
#define		seteuid(a)	setreuid(-1, (a))
#endif		/* HAVE_SETRESUID */
#endif		/* HAVE_SETEUID */

#ifndef		HAVE_SETEGID
#ifdef		HAVE_SETRESGID
#define		setegid(a)	setresgid(-1, (a), -1)
#else		/* Not HAVE_SETRESGID */
#define		setegid(a)	setregid(-1, (a))
#endif		/* HAVE_SETRESGID */
#endif		/* HAVE_SETEGID */

