/* Copyright (C) 2003-2005 by Johan van Selst (johans@stack.nl) */

/* $Id: ssl.c,v 1.26 2006/08/23 16:27:31 johans Exp $ */

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<err.h>
#include	<errno.h>
#include	<stdarg.h>

#include	<openssl/rand.h>
#include	<openssl/err.h>

#include	"config.h"
#include	"htconfig.h"
#include	"httpd.h"
#include	"path.h"
#include	"ssl.h"
#include	"extra.h"

#ifdef		HANDLE_SSL
static SSL_CTX		*ssl_ctx;
#endif		/* HANDLE_SSL */
#ifdef		HAVE_PCRE
#include		"pcre.h"
#include		<pcre.h>
#endif		/* HAVE_PCRE */

static int	netbufind, netbufsiz, readlinemode;
static char	netbuf[MYBUFSIZ];

void
setreadmode(int mode, int reset)
{
	unsigned long readerror;

	if (reset)
		netbufind = netbufsiz = 0;
#ifdef		HANDLE_SSL
	if ((readerror = ERR_get_error()))
	{
		warnx("SSL Error: %s", ERR_reason_error_string(readerror));
		error("400 SSL Error");
		return;
	}
	if (cursock->ssl)
		setenv("SSL_CIPHER", SSL_get_cipher(cursock->ssl), 1);
#endif		/* HANDLE_SSL */
	readlinemode = mode;
}

int
initssl()
{
#ifdef		HANDLE_SSL
	X509		*xs;

	if (!cursock->usessl)
		return 0;

	cursock->ssl = SSL_new(ssl_ctx);
	SSL_set_rfd(cursock->ssl, 0);
	SSL_set_wfd(cursock->ssl, 1);
	/* enable reusable keys */
	SSL_set_session_id_context(cursock->ssl,
		(const unsigned char *)SERVER_IDENT, sizeof(SERVER_IDENT));
	if (SSL_accept(cursock->ssl) < 0)
	{
		int	readerror;

		if ((readerror = ERR_get_error()))
			warnx("SSL accept error: %s",
				ERR_reason_error_string(readerror));
		else
			warnx("SSL flipped");
		return -1;
	}
	if ((xs = SSL_get_peer_certificate(cursock->ssl)))
	{
		X509_NAME	*xsname = X509_get_subject_name(xs);
		char		buffer[BUFSIZ];

		/* inform CGI about client cert */
		setenv("SSL_CLIENT_S_DN",
			(char *)X509_NAME_oneline(xsname, NULL, 0), 1);
		if (X509_NAME_get_text_by_NID(xsname, NID_commonName,
				buffer, BUFSIZ) >= 0)
			setenv("SSL_CLIENT_S_DN_CN", buffer, 1);
		if (X509_NAME_get_text_by_NID(xsname, NID_pkcs9_emailAddress,
				buffer, BUFSIZ) >= 0)
			setenv("SSL_CLIENT_S_DN_Email", buffer, 1);
		xsname = X509_get_issuer_name(xs);
		setenv("SSL_CLIENT_I_DN",
			(char *)X509_NAME_oneline(xsname, NULL, 0), 1);
		if (X509_NAME_get_text_by_NID(xsname, NID_commonName,
				buffer, BUFSIZ) >= 0)
			setenv("SSL_CLIENT_I_DN_CN", buffer, 1);
		if (X509_NAME_get_text_by_NID(xsname, NID_pkcs9_emailAddress,
				buffer, BUFSIZ) >= 0)
			setenv("SSL_CLIENT_I_DN_Email", buffer, 1);

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
				return -1;
		}
		if (cursock->sslmatchidn)
		{
			cursock->sslpcreidn =
				pcre_compile(cursock->sslmatchidn,
					0, &errormsg, &erroffset, NULL);
			if (!cursock->sslmatchidn)
				/* TODO: error handling */
				return -1;
		}
	}
#endif		/* HAVE_PCRE */
#endif		/* HANDLE_SSL */
	return 0;
}

void
endssl()
{
#ifdef		HANDLE_SSL
	if (cursock->usessl && cursock->ssl)
	{
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
	char		buffer[BUFSIZ];
	int		rc, ovector[OVSIZE];
	X509		*xs = x509_ctx->cert;

	/* match subject */
	if (cursock->sslpcresdn)
	{
		xsname = X509_get_subject_name(xs);
		X509_NAME_oneline(xsname, buffer, BUFSIZ);
		rc = pcre_exec(cursock->sslpcresdn, NULL,
			buffer, strlen(buffer),
			0, 0, ovector, OVSIZE);
		validated &= (rc >= 0);
	}
	/* match issuer */
	if (cursock->sslpcreidn)
	{
		xsname = X509_get_issuer_name(xs);
		X509_NAME_oneline(xsname, buffer, BUFSIZ);
		rc = pcre_exec(cursock->sslpcreidn, NULL,
			buffer, strlen(buffer),
			0, 0, ovector, OVSIZE);
		validated &= (rc >= 0);
	}
#endif		/* HAVE_PCRE */

	if (auth_strict == cursock->sslauth)
		return preverify_ok && validated;

	/* sslauth optional */
	(void) x509_ctx;
	return validated;
}
#endif		/* HANDLE_SSL */

void
loadssl()
{
#ifdef		HANDLE_SSL
	SSL_METHOD	*method = NULL;
	DH			*dh = NULL;
	BIO			*bio = NULL;
	struct stat	sb;

	if (!cursock->usessl)
		return;

	if (!cursock->sslcertificate)
		cursock->sslcertificate = strdup(CERT_FILE);
	if (!cursock->sslprivatekey)
		cursock->sslprivatekey = strdup(KEY_FILE);
	SSL_load_error_strings();
	SSL_library_init();
	ERR_print_errors_fp(stderr);
	if (!(method = SSLv23_server_method()))
		err(1, "Cannot init SSL method: %s",
			ERR_reason_error_string(ERR_get_error()));
	if (!(ssl_ctx = SSL_CTX_new(method)))
		err(1, "Cannot init SSL context: %s",
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_use_certificate_file(ssl_ctx,
			calcpath(cursock->sslcertificate),
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL cert %s: %s", 
			calcpath(cursock->sslcertificate),
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx,
			calcpath(cursock->sslprivatekey),
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL key %s: %s", 
			calcpath(cursock->sslprivatekey),
			ERR_reason_error_string(ERR_get_error()));
	if (!SSL_CTX_check_private_key(ssl_ctx))
		errx(1, "Cannot check private SSL %s %s: %s",
			calcpath(cursock->sslcertificate),
			calcpath(cursock->sslprivatekey),
			ERR_reason_error_string(ERR_get_error()));
	if (!cursock->sslcafile && !cursock->sslcapath)
		/* TODO: throw an error */
		cursock->sslauth = auth_none;
	else if (!SSL_CTX_load_verify_locations(ssl_ctx,
			cursock->sslcafile ? calcpath(cursock->sslcafile) : NULL,
			cursock->sslcapath ? calcpath(cursock->sslcapath) : NULL))
		errx(1, "Cannot load SSL CAfile %s and CApath %s: %s", 
			cursock->sslcafile ? calcpath(cursock->sslcafile) : "",
			cursock->sslcapath ? calcpath(cursock->sslcapath) : "",
			ERR_reason_error_string(ERR_get_error()));

	/* load randomness */
	if (lstat("/dev/urandom", &sb) == 0 && S_ISCHR(sb.st_mode))
	{
		if (!RAND_load_file("/dev/urandom", 16 * 1024))
			errx(1, "Cannot load randomness (%s): %s\n",
				"/dev/urandom", ERR_reason_error_string(ERR_get_error()));
	}

	bio = BIO_new_file(calcpath(cursock->sslprivatekey), "r");
	if (bio)
	{
		dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
		if (!dh && (bio = BIO_new_file(calcpath(cursock->sslcertificate), "r")))
			dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
		if (dh)
		{
			/* This is required for DH and DSA keys
			 * XXX: silently fail if no DH info available -> no SSL
			 */
			SSL_CTX_set_tmp_dh(ssl_ctx, dh);
			SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
			DH_free(dh);
		}
		BIO_free(bio);
#ifdef		OPENSSL_EC_NAMED_CURVE
		{
			/* Using default temp ECDH parameters */
			EC_KEY	*ecdh;
			ecdh = EC_KEY_new_by_curve_name(NID_sect163r2);
			SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
			EC_KEY_free(ecdh);
		}
#endif		/* OPENSSL_EC_NAMED_CURVE */
	}
	(void) SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

	switch (cursock->sslauth)
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
	/* we are now doing SSL-only */
	setenv("HTTPS", "on", 1);
#endif		/* HANDLE_SSL */
}


int
secread(int fd, void *buf, size_t count)
{
	int	readerror;

#ifdef		HANDLE_SSL
	if (cursock->ssl && fd == 0)
	{
		if ((readerror = SSL_read(cursock->ssl, buf, count)) < 0)
			warnx("SSL read error: %s",
				ERR_reason_error_string(readerror));
	}
	else
#endif		/* HANDLE_SSL */
	{
		if ((readerror = read(fd, buf, count)) < 0)
			warn("Read error");
	}

	if (!readerror)
		usleep(300);

	return readerror;
}

int
secwrite(const void *buf, size_t count)
{
	if (chunked)
	{
		char	head[16];
		int	len = snprintf(head, 16, "%x\r\n", count);

#ifdef		HANDLE_SSL
		if (cursock->usessl)
		{
			SSL_write(cursock->ssl, head, len);
			len = SSL_write(cursock->ssl, buf, count);
			SSL_write(cursock->ssl, "\r\n", 2);
		}
		else
#endif		/* HANDLE_SSL */
		{
			write(1, head, len);
			len = write(1, buf, count);
			write(1, "\r\n", 2);
		}
		return len;
	}

#ifdef		HANDLE_SSL
	if (cursock->usessl)
		return SSL_write(cursock->ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return write(fileno(stdout), buf, count);

}

int
secputs(const char *buf)
{
	return secwrite(buf, strlen(buf));
}

int
secprintf(const char *format, ...)
{
	va_list ap;
	char	buf[4096];

	va_start(ap, format);
	vsnprintf(buf, 4096, format, ap);
	va_end(ap);
	return secwrite(buf, strlen(buf));
}

int
readline(int rd, char *buf)
{
	char		ch, *buf2;

	buf2 = buf; *buf2 = 0;
	do
	{
		if (buf2 >= buf + MYBUFSIZ - 64)
			return(ERR_LINE);
		if (netbufind >= netbufsiz)
		{
			TRYAGAIN:
			netbufsiz = secread(rd, netbuf,
				readlinemode ? MYBUFSIZ : 1);
			if (netbufsiz == -1)
			{
				if ((errno == EAGAIN) || (errno == EINTR))
				{
					mysleep(1); goto TRYAGAIN;
				}
				warn("[%s] httpd: readline() [%d]",
					currenttime, rd);
				if (rd == 0)
					error("503 Unexpected network error");
				return(ERR_QUIT);
			}
			if (netbufsiz == 0)
			{
				if (*buf)
				{
					*buf2 = 0;
					return(ERR_NONE);
				}
				if (rd == 0)
					error("503 You closed the connection!");
				return(ERR_QUIT);
			}
			netbufind = 0;
		}
		ch = *(buf2++) = netbuf[netbufind++];
	} while (ch != '\n');
	*buf2 = 0;
	return(ERR_NONE);
}


