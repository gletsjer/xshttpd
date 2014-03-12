/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		CONSTANTS_H
#define		CONSTANTS_H

/* This is where all the user preferences are defined. You may probably
want to edit something in this file. At least have a good look at it. */

/* Configuration default file locations */

#define	HTTPD_CONF	CONFIG_DIR "/httpd.conf"

#define	MIME_TYPES	CONFIG_DIR "/mime.types"
#define	MIME_INDEX	CONFIG_DIR "/mime.index"

#define SCRIPT_METHODS	CONFIG_DIR "/script.methods"
#define	COMPRESS_METHODS CONFIG_DIR "/compress.methods"

#define	CERT_FILE	CONFIG_DIR "/cert.pem"
#define KEY_FILE	CONFIG_DIR "/key.pem"

#define CNT_DATA	DB_DIR "/counter.data"
#define CNT_LOCK	DB_DIR "/counter.lock"
#define CNT_CLEAR	DB_DIR "/clear.lock"

#define BITBUCKETNAME	"/dev/null"
#define PID_FILE	RUN_DIR "/xshttpd.pid"
#define SESSION_DIR	DB_DIR "/sessions"
#define SESSION_PATH	DB_DIR "/oldsess.db"
#define DHPARAM_FILE	DB_DIR "/dhparam.pem"
#define TEMPORARYPREFIX	"/tmp/xshttpd.XXXX"

#define INDEX_HTML	"index.html"
#define NOXS_FILE	".noxs"
#define AUTH_FILE	".xsauth"
#define REDIR_FILE	".redir"
#define CONFIG_FILE	".xsconf"

#define	CGI_DIR		"cgi-bin"
#define	ICON_DIR	"icons"
#define UHTML_DIR	".html"

#define OCTET_STREAM	"application/octet-stream"

/* The default PATH environment variable for CGI binaries */
#define SCRIPT_PATH	"/bin:/sbin:/usr/bin:/usr/sbin:" \
			"/usr/local/bin:/usr/local/sbin"

/* The default number of child processes (servers per socket). */
#define HTTPD_NUMBER	20

/* Argument to listen(). Leave it as it is, it should be fine. */
#define MAXLISTEN	50

/* Internal buffer sizes */
#define		RWBUFSIZE	4096
#define		MYBUFSIZ	1024
#define		LINEBUFSIZE	4096

/* Minimum speed to indicate progress */
#define		MINBYTESPERSEC	32

/* Parsing method for fparseln() */
#define	FPARSEARG	FPARSELN_UNESCCOMM|FPARSELN_UNESCCONT|FPARSELN_UNESCESC

/* Assumed maximum pathlength. Use C99 define */
#define	XS_PATH_MAX	((size_t)FILENAME_MAX)

#endif		/* CONSTANTS_H */
