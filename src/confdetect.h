/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
 
/* This file contains information about your system and available
library functions. You may edit this file by hand, but running the
configuration tool ./configure should take care of everything already */

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
  
/* Define SYS_TIME_WITH_TIME if your system allows including both
/sys/time.h and time.h. If your system does not allow it, undefine
SYS_TIME_WITH_TIME. */ 
  
#define SYS_TIME_WITH_TIME
  
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
  
/* Does your system support the mkstemp() library call? If not, the
httpd will use tempnam() instead - see below */
  
#define HAVE_TEMPNAM 
  
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
  
/* Does your system have a good working getaddrinfo() library call? If so,
it will be used, otherwise hostname-resolution won't work well. */
  
#define HAVE_GETADDRINFO
  
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

