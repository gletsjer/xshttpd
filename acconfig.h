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

