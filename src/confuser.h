/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		CONFUSER_H
#define		CONFUSER_H

/* This is where all the user preferences are defined. You may probably
want to edit something in this file. At least have a good look at it. */

/* The default group and user ID of the WWW server. It assumes this group
and user ID when a page or cgi-binary is requested that is not in a
user's home directory. Typically this would be 'nobody' and 'nogroup',
but you can also make a seperate user and group id, for example 'http'
and 'www'. Note that this user should be able to read the webserver data,
but not able to overwrite your data - nor should it be able to write logfiles */

#define HTTPD_USERID	"nobody"
#define HTTPD_GROUPID	"nogroup"

/* Configuration default file locations */

#define	HTTPD_CONF	CONFIG_DIRT "httpd.conf"

#define	MIME_TYPES	CONFIG_DIRT "mime.types"
#define	MIME_INDEX	CONFIG_DIRT "mime.index"

#define SCRIPT_METHODS	CONFIG_DIRT "script.methods"
#define	COMPRESS_METHODS CONFIG_DIRT "compress.methods"

#ifdef		HANDLE_SSL
#define	CERT_FILE	CONFIG_DIRT "cert.pem"
#define KEY_FILE	CONFIG_DIRT "key.pem"
#endif		/* HANDLE_SSL */

#define CNT_DATA	LOG_DIRT "xs-counter.data"
#define CNT_LOCK	LOG_DIRT "xs-counter.lock"
#define CNT_CLEAR	LOG_DIRT "xs-clear.lock"

#define BITBUCKETNAME	"/dev/null"
#define PID_PATH	"/var/run/httpd.pid"
#define TEMPORARYPREFIX	"/tmp/xs-httpd.XXXX"

#define INDEX_HTML	"index.html"
#define NOXS_FILE	".noxs"
#define AUTH_FILE	".xsauth"
#define REDIR_FILE	".redir"
#define CONFIG_FILE	".xsconf"

#define UHTML_DIR	".html"

/* The default PATH environment variable for CGI binaries */
#define SCRIPT_PATH	"/bin:/sbin:/usr/bin:/usr/sbin:" \
			"/usr/local/bin:/usr/local/sbin"

/* The default number of child processes (servers per socket). */
#define HTTPD_NUMBER	20

/* Argument to listen(). Leave it as it is, it should be fine. */
#define MAXLISTEN	50

/* Assumed maximum pathlength. Use C99 define */
#define	XS_PATH_MAX	((size_t)FILENAME_MAX)

/* Assume user/group name maximum length */
#define	XS_USER_MAX	32

/* Maximum number of configured virtual hosts */
#define	MAXVHOSTALIASES	32

/* Maximum size of configured IndexFiles */
#define	MAXINDEXFILES	32

#endif		/* CONFUSER_H */
