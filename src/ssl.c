/* Copyright (C) 2003-2013 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<sys/uio.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<ctype.h>
#include	<sys/file.h>
#include	<fcntl.h>
#ifdef		HAVE_ERR_H
# include	<err.h>
#endif		/* HAVE_ERR_H */
#include	<fnmatch.h>

#ifdef		HAVE_DB_H
# include	<db.h>
#endif		/* HAVE_DB_H */

#include	<openssl/rand.h>
#include	<openssl/err.h>
#include	<openssl/conf.h>
#include	<openssl/ssl.h>
#include	<openssl/tls1.h>
#include	<openssl/ocsp.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"path.h"
#include	"decode.h"
#include	"hash.h"
#include	"ssl.h"
#include	"extra.h"
#include	"methods.h"
#include	"malloc.h"

#ifdef		HAVE_PCRE
# include	"pcre.h"
# include	<pcre.h>
#endif		/* HAVE_PCRE */

#ifdef		HAVE_DB_H
#define		DBSESSION	"xs-session-cache.db"

static DB	*db = NULL;
static DB_ENV	*dbenv = NULL;
#endif		/* HAVE_DB_H */

static int	netbufind[2], netbufsiz[2];
static char	netbuf[2][MYBUFSIZ];
#define	bufind	netbufind[rd ? 1 : 0]
#define	bufsiz	netbufsiz[rd ? 1 : 0]
#define	sockbuf	netbuf[rd ? 1 : 0]

static int	pem_passwd_cb(char *, int, int, void *);
#ifdef	 	HANDLE_SSL_TLSEXT
static int	ssl_servername_cb(SSL *, int *, struct socket_config *);
#endif		/* HANDLE_SSL_TLSEXT */
static void	preloadssl(void);

typedef struct simple_ssl_session_st
{
	uint32_t	idlen;
	uint32_t	derlen;
	unsigned char	*id;
	unsigned char	*der;
	time_t		mtime;
	struct simple_ssl_session_st *next;
} simple_ssl_session;

#if 0
static simple_ssl_session *first = NULL;
#endif


void
initreadmode(bool reset)
{
	unsigned long readerror;

	if (reset)
	{
		netbufind[0] = netbufsiz[0] = 0;
		netbuf[0][0] = '\0';
	}
	if (cursock->ssl)
	{
		while ((readerror = ERR_get_error()))
		{
			warnx("SSL Error: %s",
				ERR_reason_error_string(readerror));
			usleep(200);
		}
		setenv("SSL_CIPHER", SSL_get_cipher(cursock->ssl), 1);
	}
}

bool
initssl(void)
{
	if (!cursock->usessl)
		return true;

	cursock->ssl = SSL_new(cursock->ssl_ctx);
	SSL_set_rfd(cursock->ssl, 0);
	SSL_set_wfd(cursock->ssl, 1);
	if (config.usesslsessionstore)
	{
		/* enable reusable keys */
		SSL_set_session_id_context(cursock->ssl,
			(const unsigned char *)SERVER_IDENT,
			sizeof(SERVER_IDENT));
	}
	if (SSL_accept(cursock->ssl) < 0)
	{
		unsigned long	readerror;

		if ((readerror = ERR_get_error()))
			warnx("SSL accept error: %s",
				ERR_reason_error_string(readerror));
		else
			warnx("SSL flipped");
		return false;
	}

#ifdef		HAVE_PCRE
	if (cursock->sslmatchsdn || cursock->sslmatchidn)
	{
		int		erroffset;
		const char	*errormsg;

		if (cursock->sslmatchsdn)
		{
			cursock->sslpcresdn =
				pcre_compile(cursock->sslmatchsdn,
					0, &errormsg, &erroffset, NULL);
			if (!cursock->sslmatchsdn)
				/* TODO: error handling */
				return false;
		}
		if (cursock->sslmatchidn)
		{
			cursock->sslpcreidn =
				pcre_compile(cursock->sslmatchidn,
					0, &errormsg, &erroffset, NULL);
			if (!cursock->sslmatchidn)
				/* TODO: error handling */
				return false;
		}
	}
#endif		/* HAVE_PCRE */
	return true;
}

void
ssl_environment(void)
{
	X509		*xs;

	if (!cursock->usessl)
		return;

	if ((xs = SSL_get_peer_certificate(cursock->ssl)))
	{
		X509_NAME	*xsname = X509_get_subject_name(xs);
		char		*text;
		int		len;

		/* inform CGI about client cert */
		/* subject */
		text = X509_NAME_oneline(xsname, NULL, 0);
		if (text)
		{
			setenv("SSL_CLIENT_S_DN", text, 1);
			FREE(text);
		}
		len = X509_NAME_get_text_by_NID(xsname, NID_commonName,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname, NID_commonName,
				text, len + 1);
			setenv("SSL_CLIENT_S_DN_CN", text, 1);
			FREE(text);
		}

		len = X509_NAME_get_text_by_NID(xsname, NID_pkcs9_emailAddress,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname,
				NID_pkcs9_emailAddress, text, len + 1);
			setenv("SSL_CLIENT_S_DN_Email", text, 1);
			FREE(text);
		}
		/* issuer */
		xsname = X509_get_issuer_name(xs);
		text = X509_NAME_oneline(xsname, NULL, 0);
		if (text)
		{
			setenv("SSL_CLIENT_I_DN", text, 1);
			FREE(text);
		}
		len = X509_NAME_get_text_by_NID(xsname, NID_commonName,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname, NID_commonName,
				text, len + 1);
			setenv("SSL_CLIENT_I_DN_CN", text, 1);
			FREE(text);
		}
		len = X509_NAME_get_text_by_NID(xsname, NID_pkcs9_emailAddress,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname,
				NID_pkcs9_emailAddress, text, len + 1);
			setenv("SSL_CLIENT_I_DN_Email", text, 1);
			FREE(text);
		}

		/* we did accept the cert, but is it valid? */
		if (SSL_get_verify_result(cursock->ssl) == X509_V_OK)
			setenv("SSL_CLIENT_VERIFY", "SUCCESS", 1);
		else
			setenv("SSL_CLIENT_VERIFY", "FAILED", 1);

		X509_free(xs);
	}
	else
	{
		unsetenv("SSL_CLIENT_S_DN");
		unsetenv("SSL_CLIENT_S_DN_CN");
		unsetenv("SSL_CLIENT_S_DN_Email");
		unsetenv("SSL_CLIENT_I_DN");
		unsetenv("SSL_CLIENT_I_DN_CN");
		unsetenv("SSL_CLIENT_I_DN_Email");
		setenv("SSL_CLIENT_VERIFY", "NONE", 1);
	}
	/* we are now doing SSL-only */
	setenv("HTTPS", "on", 1);
}

void
endssl(void)
{
	if (cursock->usessl && cursock->ssl)
	{
		if (!SSL_shutdown(cursock->ssl))
			SSL_shutdown(cursock->ssl);
		SSL_free(cursock->ssl);
		cursock->ssl = NULL;
	}
}

#if 0
static bool
store_session(void)
{
	const unsigned int	SESSION_LIMIT = 10000;
	simple_ssl_session	*sess;
	struct stat		sb;
	unsigned int		count = 0;
	int	fd, ret;
	bool	wrok;

	/* Obtain exclusive lock - may block */
#ifdef		O_EXLOCK
	fd = open(SESSION_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_EXLOCK,
			S_IRUSR | S_IWUSR);
	if (fd < 0)
		return false;
#else		/* O_EXLOCK */
	fd = open(SESSION_PATH, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR);
	if (fd < 0)
		return false;
	flock(fd, LOCK_EX);
#endif		/* O_EXLOCK */

	for (sess = first; sess; sess = sess->next)
	{
		wrok = write(fd, &sess->idlen, sizeof(sess->idlen)) >= 0 &&
			write(fd, &sess->derlen, sizeof(sess->derlen)) >= 0 &&
			write(fd, sess->id, sess->idlen) >= 0 &&
			write(fd, sess->der, sess->derlen) >= 0;
		if (!wrok)
			break;
		if (count++ > SESSION_LIMIT)
			/* Discard old entries */
			break;
	}

	flock(fd, LOCK_UN);
	ret = close(fd);
	if (ret < 0 || !wrok)
		return false;

	/* Mark in-memory version with timestamp from disk */
	ret = stat(SESSION_PATH, &sb);
	if (ret < 0)
		return false;
	first->mtime = sb.st_mtime;

	return true;
}

static bool
load_session(void)
{
	simple_ssl_session	*sess, *prev;
	struct stat		sb;
	int	fd, ret;
	bool	rdok;

	/* Check if in-memory version matches on-disk data */
	if (first)
	{
		ret = stat(SESSION_PATH, &sb);
		if (ret < 0)
			return false;
		if (sb.st_mtime <= first->mtime)
			return true;
	}

#ifdef		O_SHLOCK
	fd = open(SESSION_PATH, O_RDONLY | O_SHLOCK);
	if (fd < 0)
		return false;
#else		/* O_SHLOCK */
	fd = open(SESSION_PATH, O_RDONLY);
	if (fd < 0)
		return false;
	flock(fd, LOCK_SH);
#endif		/* O_SHLOCK */

	/* Clean old data */
	for (sess = first; (prev = sess); )
	{
		sess = sess->next;
		FREE(prev);
	}

	/* Load fresh info from disk */
	rdok = true;
	first = prev = NULL;
	while (rdok)
	{
		MALLOC(sess, simple_ssl_session, 1);
		rdok = read(fd, &sess->idlen, sizeof(sess->idlen)) >= 0 &&
			read(fd, &sess->derlen, sizeof(sess->derlen)) >= 0;
		if (!rdok || !sess->idlen || !sess->derlen)
			break;
		MALLOC(sess->id, unsigned char, sess->idlen);
		MALLOC(sess->der, unsigned char, sess->derlen);

		rdok = read(fd, sess->id, sess->idlen) >= 0 &&
			read(fd, sess->der, sess->derlen) >= 0;
		if (!rdok)
			break;

		sess->next = NULL;
		if (!first)
		{
			first = sess;
			first->mtime = sb.st_mtime;
		}
		else
			prev->next = sess;
		prev = sess;
	}
	if (!rdok)
		FREE(sess);

	flock(fd, LOCK_UN);
	close(fd);
	return first != NULL;
}

static void 
free_sessions(void)
{
	simple_ssl_session *sess,
	               *tsess;

	for (sess = first; sess;)
	{
		OPENSSL_free(sess->id);
		OPENSSL_free(sess->der);
		tsess = sess;
		sess = sess->next;
		OPENSSL_free(tsess);
	}
	first = NULL;
}
#endif		/* 0 */

#ifdef		HAVE_DB_H
static int 
add_session(struct ssl_st *ssl, SSL_SESSION *ssl_session)
{
	unsigned char  *p;
	int	ret;
	DBT	id,
		sess;

	memset(&id, 0, sizeof(id));
	memset(&sess, 0, sizeof(id));

	id.data = (unsigned char *)SSL_SESSION_get_id(ssl_session, &id.size);

	sess.size = i2d_SSL_SESSION(ssl_session, NULL);
	sess.data = OPENSSL_malloc(sess.size);
	p = sess.data;
	i2d_SSL_SESSION(ssl_session, &p);

//p = id.data; warnx("Adding  new  session (#%u) %02hhx%02hhx%02hhx%02hhx%02hhx", id.size, p[0], p[1], p[2], p[3], p[4]);
	ret = db->put(db, NULL, &id, &sess, 0);
	if (ret)
		warnx("put() failed with %d", ret);

	OPENSSL_free(sess.data);
	(void)ssl;
	return 0;
}

static SSL_SESSION *
get_session(struct ssl_st *ssl, unsigned char *sid, int idlen, int *do_copy)
{
	int	ret;
	DBT	id,
		sess;

	memset(&id, 0, sizeof(id));
	memset(&sess, 0, sizeof(id));

	id.size = idlen;
	id.data = sid;

	ret = db->get(db, NULL, &id, &sess, 0);
	if (DB_BUFFER_SMALL == ret)
	{
//warnx("Rescaling for get: %u", sess.size);
		sess.data = malloc(sess.size);
		ret = db->get(db, NULL, &id, &sess, 0);
	}

	if (!ret)
	{
		warnx("Resuming old SSL session");
//unsigned char *p = id.data; warnx("Found cached session (#%u) %02hhx%02hhx%02hhx%02hhx%02hhx", id.size, p[0], p[1], p[2], p[3], p[4]);
		return d2i_SSL_SESSION(NULL, (const unsigned char **)&sess.data, sess.size);
	}
	else if (DB_NOTFOUND == ret)
		/* */ ;
	else
		warnx("get() failed with %d", ret);
//unsigned char *p = id.data; warnx("Couldnt find session (#%u) %02hhx%02hhx%02hhx%02hhx%02hhx", id.size, p[0], p[1], p[2], p[3], p[4]);

	(void)ssl;
	(void)do_copy;
	return NULL;
}

static void 
del_session(struct ssl_ctx_st *ssl_ctx, SSL_SESSION *ssl_session)
{
	DBT	id;

//warnx("Deleting session");
	memset(&id, 0, sizeof(id));
	id.data = (void *)SSL_SESSION_get_id(ssl_session, &id.size);

	db->del(db, NULL, &id, 0);

	(void)ssl_ctx;
}

static void
init_database(void)
{
	int	ret;

	mkdir(SESSION_DIR, S_IRWXU);
	db_env_create(&dbenv, 0);
	if (!dbenv)
		errx(1, "db_env_create()");
	dbenv->set_shm_key(dbenv, 25);
	ret = dbenv->open(dbenv,
			SESSION_DIR,
			DB_CREATE | DB_SYSTEM_MEM | DB_INIT_LOCK | DB_INIT_MPOOL | DB_INIT_TXN | DB_RECOVER_FATAL,
			0);
	if (ret)
		errx(1, "DBENV->open(): %s", db_strerror(ret));
}

static void 
init_session_cache_ctx(SSL_CTX * sctx)
{
	int	ret;

	if (db)
		return;

	init_database();
	SSL_CTX_set_session_cache_mode(sctx,
			SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_SERVER);
	SSL_CTX_sess_set_new_cb(sctx, add_session);
	SSL_CTX_sess_set_get_cb(sctx, get_session);
	SSL_CTX_sess_set_remove_cb(sctx, del_session);

	db_create(&db, dbenv, 0);
	ret = db->open(db, NULL, NULL, DBSESSION, DB_BTREE, DB_CREATE, 0);
	if (ret)
		errx(1, "DB->open(): %s", db_strerror(ret));
}
#endif		/* HAVE_DB_H */

static int
sslverify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	int		validated = 1;

#ifdef		HAVE_PCRE
	X509_NAME	*xsname;
	char		*strname;
	int		rc, ovector[OVSIZE];
	X509		*xs = x509_ctx->cert;

	/* match subject */
	if (cursock->sslpcresdn)
	{
		xsname = X509_get_subject_name(xs);
		strname = X509_NAME_oneline(xsname, NULL, 0);
		if (strname)
		{
			rc = pcre_exec(cursock->sslpcresdn, NULL,
				strname, strlen(strname),
				0, 0, ovector, OVSIZE);
			validated &= (rc >= 0);
			FREE(strname);
		}
		else
			validated = false;
	}
	/* match issuer */
	if (cursock->sslpcreidn)
	{
		xsname = X509_get_issuer_name(xs);
		strname = X509_NAME_oneline(xsname, NULL, 0);
		if (strname)
		{
			rc = pcre_exec(cursock->sslpcreidn, NULL,
				strname, strlen(strname),
				0, 0, ovector, OVSIZE);
			validated &= (rc >= 0);
			FREE(strname);
		}
		else
			validated = false;
	}
#endif		/* HAVE_PCRE */

	if (auth_strict == cursock->sslauth)
		return preverify_ok && validated;

	/* sslauth optional */
	(void)x509_ctx;
	return validated;
}

static int
pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
	char	*passphrase;

	printf("Protected SSL key '%s' requires a passphrase.\n",
		(char *)userdata);
	if (!(passphrase = getpass("Passphrase: ")))
		return 0;
	strlcpy(buf, passphrase, (size_t)size);
	memset(passphrase, 0, strlen(passphrase));

	(void)rwflag;
	(void)userdata;
	return strlen(buf);
}

#ifdef	 	HANDLE_SSL_TLSEXT
static int
ssl_servername_cb(SSL *ssl, int *al, struct socket_config *lsock)
{
	const char	*servername;
	struct ssl_vhost*vhost;
	struct virtual	*vc;

	if (!(servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
	{
		/* Common issue for some clients: don't complain
		warnx("Failed to get TLS hostname");
		 */
		return SSL_TLSEXT_ERR_NOACK;
	}

	if (!lsock->sslvhosts)
		return SSL_TLSEXT_ERR_NOACK;

	for (vhost = lsock->sslvhosts; vhost; vhost = vhost->next)
	{
		vc = vhost->virtual;

		if (!strcasecmp(servername, vc->hostname))
			break;
		if (!vc->aliases)
			continue;

		if (fnmatch_array(vc->aliases, servername, FNM_CASEFOLD))
			break;
	}
	if (!vhost || !vhost->ssl_ctx)
		return SSL_TLSEXT_ERR_NOACK;

	/* matching vhost config found */
	if (vhost->ssl_ctx != SSL_set_SSL_CTX(ssl, vhost->ssl_ctx))
	{
		warnx("Failed to switch SSL context");
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	(void)al;
	return SSL_TLSEXT_ERR_OK;
}

static int
ssl_status_cb(SSL *ssl, const char *filename)
{
	BIO		*bio;
	OCSP_RESPONSE	*ostruct = NULL;
	unsigned char	*ocsp = NULL;
	size_t		ocsplen;

	if (!filename)
		return SSL_TLSEXT_ERR_NOACK;

	bio = BIO_new_file(filename, "r");
	if (!bio)
		return SSL_TLSEXT_ERR_NOACK;

	if (!d2i_OCSP_RESPONSE_bio(bio, &ostruct))
		return SSL_TLSEXT_ERR_NOACK;

#if 0
	warnx("OCSP read: %s\n", ERR_reason_error_string(ERR_get_error()));
	BIO *berr = BIO_new_fp(stderr, BIO_NOCLOSE);
	OCSP_RESPONSE_print(berr, ostruct, 2);
#endif

	/* TODO: Do some sanity checking here,
	 * discard invalid / expired information
	 */

	ocsplen = i2d_OCSP_RESPONSE(ostruct, &ocsp);
	SSL_set_tlsext_status_ocsp_resp(ssl, ocsp, ocsplen);
	return SSL_TLSEXT_ERR_OK;
}
#endif	 	/* HANDLE_SSL_TLSEXT */

static void
preloadssl(void)
{
	static bool	ssl_init_done = false;

	if (ssl_init_done)
		return;

	SSL_load_error_strings();
#ifdef		HAVE_OPENSSL_CONFIG
	OPENSSL_config(NULL);
#endif		/* HAVE_OPENSSL_CONFIG */
	SSL_library_init();
	ERR_print_errors_fp(stderr);

#ifdef		DEVRANDOM
	/* load randomness */
	/* DECL */
	struct stat	sb;
	const char	*devrandom[] = { DEVRANDOM };

	if (lstat(devrandom[0], &sb) == 0 && S_ISCHR(sb.st_mode))
	{
		if (!RAND_load_file(devrandom[0], 16 * 1024))
			errx(1, "Cannot load randomness (%s): %s\n",
				devrandom[0],
				ERR_reason_error_string(ERR_get_error()));
	}
#endif		/* DEVRANDOM */

	ssl_init_done = true;
}

void
loadssl(struct socket_config * const lsock, struct ssl_vhost * const sslvhost)
{
	SSL_CTX			*ssl_ctx;
	const SSL_METHOD	*method = NULL;
	struct virtual		*vc = NULL;

	if (!lsock->usessl)
		return;

	preloadssl();

	if (!lsock->sslcertificate)
		STRDUP(lsock->sslcertificate, CERT_FILE);
	if (!lsock->sslprivatekey)
		STRDUP(lsock->sslprivatekey, KEY_FILE);

	if (sslvhost)
	{
		vc = sslvhost->virtual;
		if (!vc->sslcertificate)
			return;
		if (!vc->sslprivatekey)
			STRDUP(vc->sslprivatekey, vc->sslcertificate);
	}

	if (!(method = SSLv23_server_method()))
		err(1, "Cannot init SSL method: %s",
			ERR_reason_error_string(ERR_get_error()));
	if (!(ssl_ctx = SSL_CTX_new(method)))
		err(1, "Cannot init SSL context: %s",
			ERR_reason_error_string(ERR_get_error()));
	if (sslvhost)
		sslvhost->ssl_ctx = ssl_ctx;
	else
		lsock->ssl_ctx = ssl_ctx;

	if (lsock->sslcipherlist)
	{
		if (!SSL_CTX_set_cipher_list(ssl_ctx, lsock->sslcipherlist))
			errx(1, "No suitable SSL cipher: %s", lsock->sslcipherlist);
	}
	else
		SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL");

#ifdef		SSL_MODE_AUTO_RETRY
	SSL_CTX_set_mode(ssl_ctx,
		SSL_CTX_get_mode(ssl_ctx) | SSL_MODE_AUTO_RETRY);
#endif		/* SSL_MODE_AUTO_RETRY */
	SSL_CTX_set_default_passwd_cb(ssl_ctx, pem_passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, lsock->sslprivatekey);

	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx,
			sslvhost ? vc->sslcertificate : lsock->sslcertificate))
		errx(1, "Cannot load SSL cert %s: %s", 
			sslvhost ? vc->sslcertificate : lsock->sslcertificate,
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx,
			sslvhost ? vc->sslprivatekey : lsock->sslprivatekey,
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL key %s: %s", 
			sslvhost ? vc->sslprivatekey : lsock->sslprivatekey,
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_check_private_key(ssl_ctx))
		errx(1, "Cannot check private SSL %s %s: %s",
			sslvhost ? vc->sslprivatekey : lsock->sslcertificate,
			sslvhost ? vc->sslprivatekey : lsock->sslprivatekey,
			ERR_reason_error_string(ERR_get_error()));

	if (!lsock->sslcafile && !lsock->sslcapath)
		/* TODO: warn */;
	else if (!SSL_CTX_load_verify_locations(ssl_ctx,
			lsock->sslcafile, lsock->sslcapath))
		errx(1, "Cannot load SSL CAfile %s and CApath %s: %s", 
			lsock->sslcafile, lsock->sslcapath,
			ERR_reason_error_string(ERR_get_error()));

	if (!lsock->sslcrlfile && !lsock->sslcrlpath)
		/* TODO: warn */;
	else if (!SSL_CTX_load_verify_locations(ssl_ctx,
			lsock->sslcrlfile, lsock->sslcrlpath))
		errx(1, "Cannot load SSL CAfile %s and CApath %s: %s", 
			lsock->sslcrlfile, lsock->sslcrlpath,
			ERR_reason_error_string(ERR_get_error()));
	else
	{
		/* explicitly enable CRL checks */
		X509_STORE	*store = SSL_CTX_get_cert_store(ssl_ctx);

		X509_STORE_set_flags(store,
			X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}

	if (lsock->sslcalist)
	{
		STACK_OF(X509_NAME)	*list;

		list = SSL_load_client_CA_file(lsock->sslcalist);
		SSL_CTX_set_client_CA_list(ssl_ctx, list);
	}

	/* read dh parameters from private keyfile */
	BIO	*bio = BIO_new_file(sslvhost ? vc->sslprivatekey : lsock->sslprivatekey, "r");
	if (bio)
	{
		DSA		*dsa;
		DH		*dh;
		BIO		*pbio;

		dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);

		if (!dh && (dsa = PEM_read_bio_DSAparams(bio, NULL, NULL, NULL)))
		{
			dh = DSA_dup_DH(dsa);
			DSA_free(dsa);
		}
		/* read dh parameters from public certificate file */
		if (!dh && (pbio = BIO_new_file(sslvhost ? vc->sslcertificate : lsock->sslcertificate, "r")))
		{
			dh = PEM_read_bio_DHparams(pbio, NULL, NULL, NULL);
			if (!dh && (dsa = PEM_read_bio_DSAparams(pbio, NULL, NULL, NULL)))
			{
				dh = DSA_dup_DH(dsa);
				DSA_free(dsa);
			}
			BIO_free(pbio);
		}
		/* read dh parameters from DHparam file */
		if (!dh && (pbio = BIO_new_file(DHPARAM_FILE, "r")))
		{
			dh = PEM_read_bio_DHparams(pbio, NULL, NULL, NULL);
			BIO_free(pbio);
		}
		/* Generate DHparam file with random value */
		if (!dh && (pbio = BIO_new_file(DHPARAM_FILE, "w")))
		{
			dh = DH_generate_parameters(2048, 2, NULL, NULL);
			PEM_write_bio_DHparams(pbio, dh);
			BIO_free(pbio);
		}
		if (dh)
		{
			/* This is required for DH and DSA keys
			 * XXX: silently fail if no DH info available -> no SSL
			 */
			SSL_CTX_set_tmp_dh(ssl_ctx, dh);
			SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
			DH_free(dh);
		}
	}

	/* Enable support for ECDHE with hard-coded curve name */
	/* This is a must for EC keys, but optional for others */
#ifdef		OPENSSL_EC_NAMED_CURVE
	EC_KEY	*ecdh;

	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ecdh)
		errx(1, "Cannot load temp curve: %s",
			ERR_reason_error_string(ERR_get_error()));
	SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
	EC_KEY_free(ecdh);
#endif		/* OPENSSL_EC_NAMED_CURVE */

	/* set up shared key for SSL tickets */
	if (config.usesslsessiontickets)
	{
		EVP_PKEY	*pkey = NULL;

		if (bio)
		{
			BIO_reset(bio);
			PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
		}

#ifdef		SSL_CTRL_SET_TLSEXT_TICKET_KEYS
		if (pkey)
		{
			/* To get our key, we sign the seed with the private key */
			const char	ticketkey[] = "xshttpd-global-ticketkey";
			unsigned char	keys[SSL_MAX_MASTER_KEY_LENGTH];
			unsigned char	sign[EVP_PKEY_size(pkey)];
			unsigned int	siglen = 0;

			EVP_MD_CTX mdctx;
			EVP_MD_CTX_init(&mdctx);
			EVP_SignInit(&mdctx, EVP_sha384());
			EVP_SignUpdate(&mdctx, ticketkey, strlen(ticketkey));
			EVP_SignFinal(&mdctx, sign, &siglen, pkey);

			/* The first 48 bytes are used:
			 * - 16 bytes ticket key name
			 * - 16 bytes hmac key
			 * - 16 bytes aes key
			 */
			memcpy(keys, sign, sizeof(keys));

			/* Work-around for old version that mis-typed this call */
#define		SSL_CTRL_SET_TLXEXT_TICKET_KEYS	SSL_CTRL_SET_TLSEXT_TICKET_KEYS
			/* Tell OpenSSL to use those keys */
			SSL_CTX_set_tlsext_ticket_keys(ssl_ctx, keys, sizeof(keys));
//warnx("key set %02x%02x%02x%02x%02x", keys[0], keys[1], keys[2], keys[3], keys[4]);
		}
#endif		/* SSL_CTRL_SET_TLSEXT_TICKET_KEYS */

		if (pkey)
			EVP_PKEY_free(pkey);
		if (bio)
			BIO_free(bio);
	}
#ifdef		SSL_OP_NO_TICKET
	else
		(void)SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
#endif		/* SSL_OP_NO_TICKET */

#ifdef		HAVE_DB_H
	/* set up store for SSL session resume */
	if (config.usesslsessionstore)
		init_session_cache_ctx(ssl_ctx);
#endif		/* HAVE_DB_H */

#ifdef		SSL_OP_NO_COMPRESSION
	(void)SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 |
			SSL_OP_NO_SSLv3 |
			SSL_OP_NO_COMPRESSION |
			SSL_OP_CIPHER_SERVER_PREFERENCE);
#else		/* SSL_OP_NO_COMPRESSION */
	(void)SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 |
			SSL_OP_NO_SSLv3 |
			SSL_OP_CIPHER_SERVER_PREFERENCE);
#endif		/* SSL_OP_NO_COMPRESSION */

	switch (lsock->sslauth)
	{
	default:
	case auth_none:
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		break;
	case auth_optional:
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, &sslverify_callback);
		break;
	case auth_strict:
		SSL_CTX_set_verify(ssl_ctx,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			&sslverify_callback);
	}

#ifdef		HANDLE_SSL_TLSEXT
	if (!SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ssl_servername_cb)
			|| !SSL_CTX_set_tlsext_servername_arg(ssl_ctx, lsock))
		errx(1, "Cannot load TLS servername callback");

	const char *ocspfile = vc && vc->sslocspfile
		? vc->sslocspfile : lsock->sslocspfile;
	if (!SSL_CTX_set_tlsext_status_cb(ssl_ctx, ssl_status_cb) ||
			!SSL_CTX_set_tlsext_status_arg(ssl_ctx, ocspfile))
		errx(1, "Cannot load TLS status callback");

	const char *infofile = vc && vc->sslinfofile
		? vc->sslinfofile : lsock->sslinfofile;
	if (infofile) {
# ifdef		HAVE_OPENSSL_SERVERINFO
		if (!SSL_CTX_use_serverinfo_file(ssl_ctx, lsock->sslinfofile))
			errx(1, "Cannot load TLS serverinfo file");
# else		/* HAVE_OPENSSL_SERVERINFO */
		errx(1, "Disable SSLinfofile: not supported by library");
# endif		/* HAVE_OPENSSL_SERVERINFO */
	}
#endif		/* HANDLE_SSL_TLSEXT */
}


static ssize_t
secread_internal(int fd, void *buf, size_t count)
{
	if (!count)
		return 0;

	if (cursock->ssl && STDIN_FILENO == fd)
	{
		int	ret;

		while ((ret = SSL_read(cursock->ssl, buf, count)) < 0)
		{
			const int s_err = SSL_get_error(cursock->ssl, ret);

			switch (s_err)
			{
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_READ:
				/* read was interrupted, but no error */
				usleep(200);
				continue;
			case SSL_ERROR_SYSCALL:
				if (EBADF != errno)
					warn("SSL_read()");
				/* else: socket closed (by alarm handler) */
				break;
			case SSL_ERROR_ZERO_RETURN:
				/* clean shutdown */
				break;
			default:
				warnx("SSL_read(): %s",
					ERR_error_string(s_err, NULL));
				break;
			}
			session.persistent = false;
			break;
		}
		if (!ret)
			/* clean shutdown or forced shutdown */
			session.persistent = false;
		return ret;
	}
	else
	{
		ssize_t	ret;

		while ((ret = read(fd, buf, count)) < 0)
		{
			switch (errno)
			{
			case EAGAIN:
				usleep(200);
				continue;
			case ECONNRESET:
			case EINTR:
				/* clean reset/timeout */
				break;
			default:
				warn("read()");
				break;
			}
			session.persistent = false;
			break;
		}
		return ret;
	}
	/* NOTREACHED */
}

size_t
secfread(void *buf, size_t size, size_t nmemb, FILE *stream)
{
	return (size_t)secread(fileno(stream), buf, size * nmemb);
}

ssize_t
secwrite(const char * const buf, size_t count)
{
	int		i;
	size_t		len[3];
	const char	*message[3];

	if (!count)
		return 0;

	if (session.chunked)
	{
		static char	head[20];

		i = 0;
		len[0] = (size_t)snprintf(head, sizeof(head), "%zx\r\n", count);
		len[1] = count;
		len[2] = 2;
		message[0] = head;
		message[1] = buf;
		message[2] = "\r\n";
	}
	else
	{
		i = 2;
		len[2] = count;
		message[2] = buf;
	}

	checksum_update(buf, count);

	for (; i < 3; i++)
	{
		if (cursock->usessl)
		{
			ssize_t		ret;

			while ((ret = SSL_write(cursock->ssl, message[i], len[i])) <= 0)
			{
				/* SSL_write doesn't return w/ partial writes */
				const int s_err = SSL_get_error(cursock->ssl, ret);

				switch (s_err)
				{
				case SSL_ERROR_WANT_WRITE:
					usleep(200);
					continue;
				case SSL_ERROR_SYSCALL:
					warn("SSL_write()");
					session.persistent = false;
					return ret;
				default:
					warnx("SSL_write(): %s",
						ERR_error_string(s_err, NULL));
					session.persistent = false;
					return ret;
				}
				/* NOTREACHED */
			}
		}
		else
		{
			ssize_t		ret;

			while ((ret = write(1, message[i], len[i])) < (int)len[i])
			{
				if (ret >= 0)
				{
					len[i] -= ret;
					message[i] += ret;
					usleep(200);
				}
				else if (errno == EAGAIN || errno == EINTR)
					usleep(200);
				else if (errno == EPIPE)
				{
					/* remote host aborted connection */
					session.persistent = false;
					return ret;
				}
				else
				{
					warn("write()");
					session.persistent = false;
					return ret;
				}
			}
		}
	}

	return (ssize_t)count;
}

/* NOTE: iov must have extra elements iov[-1] and iov[iovcnt] available
 * these are used to store the chunk-info data for HTTP/1.1 transmits
 */
ssize_t
secwritev(struct iovec *iov, int iovcnt)
{
	int	i;
	ssize_t	sz = 0;

	if (!iovcnt)
		return sz;

	if (cursock->usessl)
	{
		for (i = 0; i < iovcnt; i++)
			sz += secwrite(iov[i].iov_base, iov[i].iov_len);
		return sz;
	}

	if (!session.chunked)
		return writev(1, iov, iovcnt);

	/* add additional meta-data using reserved elements */
	struct iovec	*piov = iov;
	char		head[20],
			sep[3] = "\r\n";

	for (sz = i = 0; i < iovcnt; i++, piov++)
		sz += piov->iov_len;

	piov = &iov[-1];
	piov->iov_base = head;
	piov->iov_len = snprintf(head, sizeof(head), "%zx\r\n", sz);
	iov[iovcnt].iov_base = sep;
	iov[iovcnt].iov_len = 2;

	while (1)
	{
		sz = writev(1, piov, iovcnt + 2);
		if (sz >= 0)
			break;
		else if (errno == EAGAIN || errno == EINTR)
			usleep(200);
		else if (errno == EPIPE)
		{
			/* remote host aborted connection */
			session.persistent = false;
			break;
		}
		else
		{
			warn("writev()");
			session.persistent = false;
			break;
		}
	}
	return sz;
}

size_t
secfwrite(const char * const buf, size_t size, size_t nmemb, FILE *stream)
{
	(void)stream;
	return (size_t)secwrite(buf, size * nmemb);
}

ssize_t
secputs(const char * const buf)
{
	return buf ? secwrite(buf, strlen(buf)) : 0;
}

ssize_t
secprintf(const char * const format, ...)
{
	va_list 	ap;
	char		*str = NULL;

	if (!format)
		return 0;

	va_start(ap, format);
	int	len;
	VASPRINTFVAL(len, &str, format, ap);
	va_end(ap);

	if (!len)
		return 0;

	const ssize_t	ssz = secwrite(str, strlen(str));
	FREE(str);
	return ssz;
}

ssize_t
secread(int rd, void *buf, size_t len)
{
	const size_t	inbuffer = bufsiz - bufind;
	char		*cbuf = buf;

	if (!len)
		return 0;

	if (inbuffer > 0)
	{
		if (len >= inbuffer)
		{
			memcpy(buf, &sockbuf[bufind], inbuffer);
			bufsiz = bufind = 0;
			cbuf += inbuffer;
			len -= inbuffer;
		}
		else
		{
			memcpy(buf, &sockbuf[bufind], len);
			bufind += len;
			return len;
		}
	}
	return inbuffer + secread_internal(rd, cbuf, len);
}

xs_error_t
readline(int rd, char *buf, size_t len)
{
	char		ch, *buf2;

	buf2 = buf; *buf2 = 0;
	do
	{
		if (buf2 >= buf + len)
			return(ERR_LINE);
		if (bufind >= bufsiz)
		{
			/* empty buffer: read new data */
			bufind = 0;
			if ((bufsiz = secread_internal(rd, sockbuf, MYBUFSIZ)) < 0)
				switch (errno)
				{
				case EINTR:
				case ECONNRESET:
					return(ERR_CLOSE);
				default:
					return(ERR_QUIT);
				}
			else if (!bufsiz)
				/* no error, no data */
				return(ERR_CLOSE);
		}
		ch = *(buf2++) = sockbuf[bufind++];
	} while (ch != '\n');
	*buf2 = '\0';
	while (buf2-- > buf)
		if (*buf2 < ' ' && *buf2 > 0)
			*buf2 = '\0';
	return(ERR_NONE);
}

ssize_t
readheaders(int rd, struct maplist *headlist)
{
	char		input[LINEBUFSIZE];

	headlist->size = 0;
	headlist->elements = NULL;
	if (rd)
		bufind = bufsiz = 0;

	while (1)
	{
		char	*value;

		switch (readline(rd, input, LINEBUFSIZE))
		{
		case ERR_NONE:
			break;
		case ERR_QUIT:
		default:
			maplist_free(headlist);
			return -1;
		case ERR_LINE:
			maplist_free(headlist);
			return -1;
		}

		if (!input[0])
			break;
		if (!headlist->size && strncasecmp("Status:", input, 7))
		{
			char	*p;

			/* Reserve first field for 'status' line */
			headlist->size = 1;
			MALLOC(headlist->elements, struct mapping, 1);
			STRDUP(headlist->elements[0].index, "Status");
			if (!(value = strchr(input, ':')))
			{
				STRDUP(headlist->elements[0].value, input);
				if ((p = strchr(input, ' ')))
					if (!strchr(p + 1, ' '))
						/* no version: no headers */
						return 1;
				continue;
			}
			else
				STRDUP(headlist->elements[0].value, "200 OK");

		}
		if (headlist->size && isspace(input[0]))
		{
			size_t	len;
			char	*val;

			/* continue previous header */
			value = input;
			while (*value && isspace(*value))
				value++;

			val = headlist->elements[headlist->size-1].value;
			len = strlen(val) + strlen(value) + 2;
			REALLOC(val, char, len);
			strcat(val, " ");
			strcat(val, value);
			headlist->elements[headlist->size-1].value = val;
		}
		else if (headlist->size &&
				!strncasecmp(input, "Status:", 7) && input[7])
		{
			FREE(headlist->elements[0].value);
			STRDUP(headlist->elements[0].value, input + 8);
		}
		else if ((value = strchr(input, ':')))
		{
			size_t	sz;

			*value++ = '\0';
			while (*value && isspace(*value))
				value++;
			for (sz = 0; sz < headlist->size; sz++)
			{
				/* append to earlier header */
				const char * const idx = headlist->elements[sz].index;
				if (!strcasecmp(idx, "set-cookie"))
					continue;
				if (!strcasecmp(idx, input))
				{
					size_t	len;
					char	*val;
					
					val = headlist->elements[sz].value;
					len = strlen(val) + strlen(value) + 3;
					REALLOC(val, char, len);
					strcat(val, ", ");
					strcat(val, value);
					headlist->elements[sz].value = val;
					break;
				}
			}
			/* add new header */
			if (sz == headlist->size)
			{
				REALLOC(headlist->elements,
					struct mapping, sz + 1);
				STRDUP(headlist->elements[sz].index, input);
				STRDUP(headlist->elements[sz].value, value);
				headlist->size++;
			}
		}
	}

	return (ssize_t)headlist->size;
}

