/* Copyright (C) 2003-2005 by Johan van Selst (johans@stack.nl) */

/* $Id: ssl.c,v 1.15 2005/11/29 19:47:38 johans Exp $ */

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<err.h>
#include	<errno.h>
#include	<stdarg.h>

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
	if ((readerror = ERR_get_error())) {
		fprintf(stderr, "SSL Error: %s\n",
			ERR_reason_error_string(readerror));
		error("400 SSL Error");
		return;
	}
	if (cursock->ssl)
		setenv("SSL_CIPHER", SSL_get_cipher(cursock->ssl), 1);
#endif		/* HANDLE_SSL */
	readlinemode = mode;
}

int
initssl(int csd)
{
#ifdef		HANDLE_SSL
	X509		*xs;
	static const unsigned char	sid_ctx[] = SERVER_IDENT;

	if (!cursock->usessl)
		return 0;

	cursock->ssl = SSL_new(ssl_ctx);
	SSL_set_fd(cursock->ssl, csd);
	/* enable reusable keys */
	SSL_set_session_id_context(cursock->ssl, sid_ctx, 7);
	if (!SSL_accept(cursock->ssl)) {
		fprintf(stderr, "SSL flipped\n");
		secprintf("%s 500 Failed\r\nContent-type: text/plain\r\n\r\n",
			version);
		secprintf("SSL Flipped...\n");
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
endssl(int csd)
{
#ifdef		HANDLE_SSL
	SSL_free(cursock->ssl);
#endif		/* HANDLE_SSL */
	close(csd);
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
	SSL_METHOD *method;
	if (!cursock->usessl)
		return;

	if (!cursock->sslcertificate)
		cursock->sslcertificate = strdup(CERT_FILE);
	if (!cursock->sslprivatekey)
		cursock->sslprivatekey = strdup(KEY_FILE);
	SSLeay_add_all_algorithms();
	SSL_load_error_strings();
	ERR_print_errors_fp(stderr);
	if (!(method = SSLv23_server_method()))
		err(1, "Cannot init SSL method");
	if (!(ssl_ctx = SSL_CTX_new(method)))
		err(1, "Cannot init SSL context");
	if (!SSL_CTX_use_certificate_file(ssl_ctx,
			calcpath(cursock->sslcertificate),
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL cert %s", 
			calcpath(cursock->sslcertificate));
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx,
			calcpath(cursock->sslprivatekey),
			SSL_FILETYPE_PEM))
		errx(1, "Cannot load SSL key %s", 
			calcpath(cursock->sslprivatekey));
	if (!SSL_CTX_check_private_key(ssl_ctx))
		errx(1, "Cannot check private SSL %s %s",
			calcpath(cursock->sslcertificate),
			calcpath(cursock->sslprivatekey));
	if (!cursock->sslcafile && !cursock->sslcapath)
		/* TODO: throw an error */
		cursock->sslauth = auth_none;
	else if (!SSL_CTX_load_verify_locations(ssl_ctx,
			cursock->sslcafile ? calcpath(cursock->sslcafile) : NULL,
			cursock->sslcapath ? calcpath(cursock->sslcapath) : NULL))
		errx(1, "Cannot load SSL CAfile %s and CApath %s", 
			cursock->sslcafile ? calcpath(cursock->sslcafile) : "",
			cursock->sslcapath ? calcpath(cursock->sslcapath) : "");
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
#ifdef		HANDLE_SSL
	if (cursock->ssl && fd == 0)
		return SSL_read(cursock->ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return read(fd, buf, count);
}

int
secwrite(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (cursock->usessl)
		return SSL_write(cursock->ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return write(fd, buf, count);
}

int
secfwrite(void *buf, size_t size, size_t count, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (cursock->usessl)
		return SSL_write(cursock->ssl, buf, size), count;
	else
#endif		/* HANDLE_SSL */
		return fwrite(buf, size, count, stream);
}

int
secprintf(const char *format, ...)
{
	va_list ap;
	char	buf[4096];

	va_start(ap, format);
	vsnprintf(buf, 4096, format, ap);
	va_end(ap);
#ifdef		HANDLE_SSL
	if (cursock->usessl)
		return SSL_write(cursock->ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return printf("%s", buf);
}

int
secfputs(char *buf, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (cursock->usessl)
		return SSL_write(cursock->ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return fputs(buf, stream);
}

int
readline(int rd, char *buf)
{
	char		ch, *buf2;

	buf2 = buf; *buf2 = 0;
	do
	{
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
				fprintf(stderr, "[%s] httpd: readline(): %s [%d]\n",
					currenttime, strerror(errno), rd);
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
	} while ((ch != '\n') && (buf2 < (buf + MYBUFSIZ - 64)));
	*buf2 = 0;
	return(ERR_NONE);
}


