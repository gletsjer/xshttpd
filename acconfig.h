/* Do you want to enable server side includes? Server side includes
allow users to include files from within a file, have access to a
visitor counter, and display all kinds of nice things. See README.html
for more information about these SSI's. */
  
#undef WANT_SSI 

/* IPv6 support. Define this if your machine understands IPv6 internet
 * sockets and you want the httpd to listen to these as well. */
 
#undef INET6

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
 
#undef SIMPLE_VIRTUAL_HOSTING

/* When using virtual hosting, use the effective uid of the owner of
 * the virtual root directory instead of the unprivileged http user */

#undef VIRTUAL_UID

/* Define this if you want to allow certain hosts to read a directory even
 * if it contains a .noxs file. You can list the IP numbers of the host
 * that should have access in the .noxs file (no hostnames). You may list
 * only the start of an IP number to allow a range of hostnames.
 * E.g. if .noxs contains 192.168.1, access will be granted to
 * 192.168.1.0 - 192.168.1.255 and denied to the rest of the world. */
 
#undef RESTRICTXS

/* Generic file interpretation support (read: PHP)
 * This extension allows files with certain extensions to be parsed
 * by an external interpreter. You will have to specify the extensions
 * and programs in SCRIPT_METHODS
 */
 
#undef HANDLE_SCRIPT
#define SCRIPT_METHODS "script.methods"

/* The server can automatically uncompress compressed files on the server
side if the other side is not able to handle the compression method.
If you want to turn on this feature, define HANDLE_COMPRESSED. See the
default compress.methods for more details. */
  
#undef HANDLE_COMPRESSED 
#define COMPRESS_METHODS "compress.methods"

/* The server can automatically send extra font information obtained
from .charset files. Define HANDLE_CHARSET if that is what you want */
  
#undef HANDLE_CHARSET

/* The path in which `ppmtogif' (part of the NetPBM package) can be found.
If you do not have this, the graphical counter will not work (I'm
working on this...). In that case, #undef this line. */
  
#define PATH_PPMTOGIF "/usr/local/bin/ppmtogif"
  
/* The default root directory for the server. This is where the subdirs
'logs', 'htdocs' and 'cgi-bin' go. This is used as a base directory
for other directories (see below). It can be overridden from the
command line. */
  
#define HTTPD_ROOT "/usr/local/lib/httpd"

/* Fill in the name of your domain here, including the leading dot.
This is used to strip out refers that come from your own site
(which are usually not interesting). If you want all refers,
undefine THISDOMAIN. This can be overridden on the command line. */
  
#define THISDOMAIN ".stack.nl"
  
/* Do we want to use setrlimit() to limit CGI programs in what they do? */
 
#undef USE_SETRLIMIT 

/* If you need to declare sys_errlist and sys_nerr in the program itself,
define NEED_SYS_ERRLIST_DECL. */
 
#undef NEED_SYS_ERRLIST_DECL 

/* Does your system declare optarg and optind by itself? If not, the
programs will declare it themselves. If you need the programs to
declare the symbols by themselves, #define NEED_OPTARG_AND_OPTIND. */
  
#undef NEED_OPTARG_AND_OPTIND 

/* Does your system declare environ by itself? If not, the prorgams will
declare it themselves. If you need the programs to declare the symbols,
then #define NEED_DECL_ENVIRON. */
 
#undef NEED_DECL_ENVIRON 

/* Does your system have the define PRIO_MAX? If not, the programs will
declare it themselves when needed for setpriority(). 20 sounds nice */

#undef NEED_PRIO_MAX

/* Does your system have a broken getnameinfo() function?
Note: Linux distributions are well know for this feature */

#undef BROKEN_GETNAMEINFO

/* Needed by automake/autoconf */

#undef VERSION

#undef PACKAGE

