/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
 
/* This is where all the user preferences are defined. You may probably
want to edit something in this file. At least have a good look at it. */

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

/* Do we want to use setrlimit() to limit CGI programs in what they do? */
  
#define DONT_USE_SETRLIMIT 
  
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
  
#define TEMPORARYPREFIX "/tmp/xs-httpd.XXXX"

/* The default PATH environment variable that CGI binaries are started
with. This is so users' binaries can find the programs that they
depend on. The path must be given in the normal /bin/sh format. */
  
#define SCRIPT_PATH "/usr/bin:/bin:/usr/local/bin"
  
/* The name of the access authority file */
  
#define AUTHFILE ".xsauth"
  
/* Argument to listen(). Leave it as it is, it should be fine. */
  
#define MAXLISTEN 50

/* Assumed maximum pathlength. Hmmm, this looks like a nice number... */
 
#define		XS_PATH_MAX	1024

