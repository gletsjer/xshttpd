/* Copyright (C) 2003-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<ctype.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */

#ifdef		HANDLE_SSL
#include	<openssl/rand.h>
#include	<openssl/err.h>
#include	<openssl/conf.h>
#include	<openssl/e_os.h>
#include	<openssl/tls1.h>
#endif		/* HANDLE_SSL */

#include	"htconfig.h"
#include	"httpd.h"
#include	"path.h"
#include	"ssl.h"
#include	"extra.h"
#include	"methods.h"
#include	"malloc.h"

#ifdef		HAVE_PCRE
#include		"pcre.h"
#include		<pcre.h>
#endif		/* HAVE_PCRE */

static int	netbufind, netbufsiz;
static char	netbuf[MYBUFSIZ];

static int	pem_passwd_cb(char *, int, int, void *);
#ifdef	 	HANDLE_SSL_TLSEXT
static int	ssl_servername_cb(SSL *, int *, struct socket_config *);
#endif		/* HANDLE_SSL_TLSEXT */
static void	preloadssl(void);

void
initreadmode(bool reset)
{
#ifdef		HANDLE_SSL
	unsigned long readerror;
#endif		/* HANDLE_SSL */

	if (reset)
	{
		netbufind = netbufsiz = 0;
		netbuf[netbufind] = '\0';
	}
#ifdef		HANDLE_SSL
	while ((readerror = ERR_get_error()))
	{
		warnx("SSL Error: %s", ERR_reason_error_string(readerror));
		usleep(200);
	}
	if (cursock->ssl)
		setenv("SSL_CIPHER", SSL_get_cipher(cursock->ssl), 1);
#endif		/* HANDLE_SSL */
}

bool
initssl()
{
#ifdef		HANDLE_SSL
	if (!cursock->usessl)
		return true;

	cursock->ssl = SSL_new(cursock->ssl_ctx);
	SSL_set_rfd(cursock->ssl, 0);
	SSL_set_wfd(cursock->ssl, 1);
	/* enable reusable keys */
	SSL_set_session_id_context(cursock->ssl,
		(const unsigned char *)SERVER_IDENT, sizeof(SERVER_IDENT));
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
#endif		/* HANDLE_SSL */
	return true;
}

void
ssl_environment()
{
#ifdef		HANDLE_SSL
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
			free(text);
		}
		len = X509_NAME_get_text_by_NID(xsname, NID_commonName,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname, NID_commonName,
				text, len + 1);
			setenv("SSL_CLIENT_S_DN_CN", text, 1);
			free(text);
		}

		len = X509_NAME_get_text_by_NID(xsname, NID_pkcs9_emailAddress,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname,
				NID_pkcs9_emailAddress, text, len + 1);
			setenv("SSL_CLIENT_S_DN_Email", text, 1);
			free(text);
		}
		/* issuer */
		xsname = X509_get_issuer_name(xs);
		text = X509_NAME_oneline(xsname, NULL, 0);
		if (text)
		{
			setenv("SSL_CLIENT_I_DN", text, 1);
			free(text);
		}
		len = X509_NAME_get_text_by_NID(xsname, NID_commonName,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname, NID_commonName,
				text, len + 1);
			setenv("SSL_CLIENT_I_DN_CN", text, 1);
			free(text);
		}
		len = X509_NAME_get_text_by_NID(xsname, NID_pkcs9_emailAddress,
			NULL, 0);
		if (len >= 0)
		{
			MALLOC(text, char, len + 1);
			X509_NAME_get_text_by_NID(xsname,
				NID_pkcs9_emailAddress, text, len + 1);
			setenv("SSL_CLIENT_I_DN_Email", text, 1);
			free(text);
		}

		/* we did accept the cert, but is it valid? */
		if (SSL_get_verify_result(cursock->ssl) == X509_V_OK)
			setenv("SSL_CLIENT_VERIFY", "SUCCESS", 1);
		else
			setenv("SSL_CLIENT_VERIFY", "FAILED", 1);
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
#endif		/* HANDLE_SSL */
}

void
endssl()
{
#ifdef		HANDLE_SSL
	if (cursock->usessl && cursock->ssl)
	{
		if (!SSL_shutdown(cursock->ssl))
			SSL_shutdown(cursock->ssl);
		SSL_free(cursock->ssl);
		cursock->ssl = NULL;
	}
#endif		/* HANDLE_SSL */
}

#ifdef		HANDLE_SSL
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
			free(strname);
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
			free(strname);
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
		warnx("Failed to get TLS hostname");
		return SSL_TLSEXT_ERR_NOACK;
	}

	if (!lsock->sslvhosts)
		return SSL_TLSEXT_ERR_NOACK;

	for (vhost = lsock->sslvhosts; vhost; vhost = vhost->next)
	{
		char	*host;

		vc = vhost->virtual;

		if (!strcasecmp(servername, vc->hostname))
			break;
		if (!vc->aliases)
			continue;

		for (int j = 0; (host = vc->aliases[j]); j++)
			if (!strcasecmp(servername, host))
				break;

		if (host)
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
#endif		/* HANDLE_SSL */

void
loadssl(struct socket_config *lsock, struct ssl_vhost *sslvhost)
{
#ifdef		HANDLE_SSL
	SSL_CTX		*ssl_ctx;
	SSL_METHOD	*method = NULL;
	struct virtual	*vc = NULL;

	if (!lsock->usessl)
		return;

	preloadssl();

	if (!lsock->sslcertificate)
		STRDUP(lsock->sslcertificate, CERT_FILE);
	if (!lsock->sslprivatekey)
		STRDUP(lsock->sslprivatekey, KEY_FILE);

	if (sslvhost)
		vc = sslvhost->virtual;
	if (sslvhost && !vc->sslcertificate)
		return;
	if (sslvhost && !vc->sslprivatekey)
		STRDUP(vc->sslprivatekey, vc->sslcertificate);

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

#if 0
	SSL_CTX_set_mode(ssl_ctx,
		SSL_CTX_get_mode(ssl_ctx) | SSL_MODE_AUTO_RETRY);
#endif
	SSL_CTX_set_default_passwd_cb(ssl_ctx, pem_passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, lsock->sslprivatekey);

	if (!SSL_CTX_use_certificate_file(ssl_ctx,
			calcpath(sslvhost ? vc->sslcertificate : lsock->sslcertificate),
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL cert %s: %s", 
			calcpath(sslvhost ? vc->sslcertificate : lsock->sslcertificate),
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx,
			calcpath(sslvhost ? vc->sslprivatekey : lsock->sslprivatekey),
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL key %s: %s", 
			calcpath(sslvhost ? vc->sslprivatekey : lsock->sslprivatekey),
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_check_private_key(ssl_ctx))
		errx(1, "Cannot check private SSL %s %s: %s",
			calcpath(sslvhost ? vc->sslprivatekey : lsock->sslcertificate),
			calcpath(sslvhost ? vc->sslprivatekey : lsock->sslprivatekey),
			ERR_reason_error_string(ERR_get_error()));

	if (!lsock->sslcafile && !lsock->sslcapath)
		/* TODO: warn */;
	else if (!SSL_CTX_load_verify_locations(ssl_ctx,
			lsock->sslcafile ? calcpath(lsock->sslcafile) : NULL,
			lsock->sslcapath ? calcpath(lsock->sslcapath) : NULL))
		errx(1, "Cannot load SSL CAfile %s and CApath %s: %s", 
			lsock->sslcafile ? calcpath(lsock->sslcafile) : "",
			lsock->sslcapath ? calcpath(lsock->sslcapath) : "",
			ERR_reason_error_string(ERR_get_error()));

	/* read dh parameters from private keyfile */
	BIO	*bio = BIO_new_file(calcpath(sslvhost ? vc->sslprivatekey : lsock->sslprivatekey), "r");
	if (bio)
	{
		DSA		*dsa;
		DH		*dh;

		dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);

		if (!dh && (dsa = PEM_read_bio_DSAparams(bio, NULL, NULL, NULL)))
		{
			dh = DSA_dup_DH(dsa);
			DSA_free(dsa);
		}
		/* read dh parameters from public certificate file */
		if (!dh)
		{
			BIO_free(bio);
			bio = BIO_new_file(calcpath(sslvhost ? vc->sslcertificate : lsock->sslcertificate), "r");
			if (bio)
				dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
			if (!dh && (dsa = PEM_read_bio_DSAparams(bio, NULL, NULL, NULL)))
			{
				dh = DSA_dup_DH(dsa);
				DSA_free(dsa);
			}
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
		if (bio)
			BIO_free(bio);
	}
#ifdef		OPENSSL_EC_NAMED_CURVE
	{
		/* Using default temp ECDH parameters */
		EC_KEY	*ecdh;

		ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (!ecdh)
			errx(1, "Cannot load temp curve: %s",
				ERR_reason_error_string(ERR_get_error()));
		SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif		/* OPENSSL_EC_NAMED_CURVE */
	(void)SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

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
#endif		/* HANDLE_SSL_TLSEXT */

#endif		/* HANDLE_SSL */
}


static ssize_t
secread_internal(int fd, void *buf, size_t count)
{
	if (!count)
		return 0;

#ifdef		HANDLE_SSL
	if (cursock->ssl && STDIN_FILENO == fd)
	{
		int	ret;

		while ((ret = SSL_read(cursock->ssl, buf, count)) < 0)
		{
			int	s_err = SSL_get_error(cursock->ssl, ret);

			switch (s_err)
			{
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_READ:
				usleep(200);
				continue;
			case SSL_ERROR_SYSCALL:
				warn("SSL_read()");
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
#endif		/* HANDLE_SSL */
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
secwrite(const char *buf, size_t count)
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

#ifdef		HAVE_LIBMD
	if (md5context)
		MD5Update(md5context, (const unsigned char *)buf, count);
#endif		/* HAVE_LIBMD */

	for (; i < 3; i++)
	{
#ifdef		HANDLE_SSL
		if (cursock->usessl)
		{
			int		s_err;
			ssize_t		ret;

			while ((ret = SSL_write(cursock->ssl, message[i], len[i])) <= 0)
			{
				/* SSL_write doesn't return w/ partial writes */
				s_err = SSL_get_error(cursock->ssl, ret);

				switch (s_err)
				{
				case SSL_ERROR_WANT_WRITE:
					usleep(200);
					continue;
				case SSL_ERROR_SYSCALL:
					warn("SSL_write()");
					break;
				default:
					warnx("SSL_write(): %s",
						ERR_error_string(s_err, NULL));
					break;
				}
				session.persistent = false;
				break;
			}
		}
		else
#endif		/* HANDLE_SSL */
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
					break;
				}
				else
				{
					warn("write()");
					session.persistent = false;
					break;
				}
			}
		}
	}

	return (ssize_t)count;
}

size_t
secfwrite(const char *buf, size_t size, size_t nmemb, FILE *stream)
{
	(void)stream;
	return (size_t)secwrite(buf, size * nmemb);
}

ssize_t
secputs(const char *buf)
{
	return buf ? secwrite(buf, strlen(buf)) : 0;
}

ssize_t
secprintf(const char *format, ...)
{
	va_list 	ap;
	char		*str = NULL;

	if (!format)
		return 0;

	va_start(ap, format);
	const int	len = vasprintf(&str, format, ap);
	va_end(ap);

	if (!len)
		return 0;

	const ssize_t	ssz = secwrite(str, strlen(str));
	free(str);
	return ssz;
}

ssize_t
secread(int rd, void *buf, size_t len)
{
	const size_t	inbuffer = netbufsiz - netbufind;
	char		*cbuf = buf;

	if (!len)
		return 0;

	if (inbuffer > 0)
	{
		if (len >= inbuffer)
		{
			memcpy(buf, &netbuf[netbufind], inbuffer);
			netbufsiz = netbufind = 0;
			cbuf += inbuffer;
			len -= inbuffer;
		}
		else
		{
			memcpy(buf, &netbuf[netbufind], len);
			netbufind += len;
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
		if (netbufind >= netbufsiz)
		{
			/* empty buffer: read new data */
			netbufind = 0;
			if ((netbufsiz = secread_internal(rd, netbuf, MYBUFSIZ)) < 0)
				switch (errno)
				{
				case EINTR:
				case ECONNRESET:
					return(ERR_CLOSE);
				default:
					return(ERR_QUIT);
				}
			else if (!netbufsiz)
				/* no error, no data */
				return(ERR_CLOSE);
		}
		ch = *(buf2++) = netbuf[netbufind++];
	} while (ch != '\n');
	*buf2 = '\0';
	while (buf2-- > buf)
		if (*buf2 <= ' ' && *buf2 > 0)
			*buf2 = '\0';
		else
			break;
	return(ERR_NONE);
}

ssize_t
readheaders(int rd, struct maplist *headlist)
{
	char		input[LINEBUFSIZE];

	headlist->size = 0;
	headlist->elements = NULL;
	while (1)
	{
		char	*value;

		switch (readline(rd, input, LINEBUFSIZE))
		{
		case ERR_NONE:
			break;
		case ERR_QUIT:
		default:
			freeheaders(headlist);
			return -1;
		case ERR_LINE:
			freeheaders(headlist);
			return -1;
		}

		if (!input[0])
			break;
		if (isspace(input[0]))
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
		else if (!headlist->size)
		{
			/* first 'status' line is special */
			MALLOC(headlist->elements, struct mapping, 1);
			STRDUP(headlist->elements[0].index, "Status");
			STRDUP(headlist->elements[0].value, input);
			headlist->size = 1;
		}
	}

	return (ssize_t)headlist->size;
}

void
freeheaders(struct maplist *headlist)
{
	size_t		sz;

	for (sz = 0; sz < headlist->size; sz++)
	{
		free(headlist->elements[sz].index);
		free(headlist->elements[sz].value);
	}
	free(headlist->elements);
	headlist->size = 0;
	headlist->elements = NULL;
}

