/* Copyright (C) 2003-2005 by Johan van Selst (johans@stack.nl) */

/* $Id: ssl.c,v 1.2 2005/01/22 11:31:24 johans Exp $ */

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<err.h>
#include	<errno.h>
#include	<stdarg.h>

#include	"httpd.h"
#include	"htconfig.h"
#include	"config.h"
#include	"path.h"
#include	"ssl.h"
#include	"extra.h"

#ifdef		HANDLE_SSL
SSL_CTX			*ssl_ctx;
static SSL		*ssl;
#endif		/* HANDLE_SSL */

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
	}
#endif		/* HANDLE_SSL */
	readlinemode = mode;
}

int
initssl(int csd)
{
	if (!config.usessl)
		return 0;

#ifdef		HANDLE_SSL
	ssl = SSL_new(ssl_ctx);
	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
	SSL_set_fd(ssl, csd);
	if (!SSL_accept(ssl)) {
		fprintf(stderr, "SSL flipped\n");
		secprintf("%s 500 Failed\r\nContent-type: text/plain\r\n\r\n",
			version);
		secprintf("SSL Flipped...\n");
		return -1;
	}
	setenv("SSL_CIPHER", SSL_get_cipher(ssl), 1);
#endif		/* HANDLE_SSL */
	return 0;
}

void
endssl(int csd)
{
#ifdef		HANDLE_SSL
	SSL_free(ssl);
#endif		/* HANDLE_SSL */
	close(csd);
}

void
loadssl()
{
	if (!config.usessl)
		return;

#ifdef		HANDLE_SSL
	if (!config.sslcertificate)
		config.sslcertificate = strdup(CERT_FILE);
	if (!config.sslprivatekey)
		config.sslprivatekey = strdup(KEY_FILE);
	SSLeay_add_all_algorithms();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!SSL_CTX_use_certificate_file(ssl_ctx,
			calcpath(config.sslcertificate),
			SSL_FILETYPE_PEM) ||
		!SSL_CTX_use_PrivateKey_file(ssl_ctx,
			calcpath(config.sslprivatekey),
			SSL_FILETYPE_PEM) ||
		!SSL_CTX_check_private_key(ssl_ctx))
		errx(1, "Cannot initialise SSL %s %s",
			calcpath(config.sslcertificate),
			calcpath(config.sslprivatekey));
	ERR_print_errors_fp(stderr);
#endif		/* HANDLE_SSL */
}


int
secread(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (config.usessl && fd == 0)
		return SSL_read(ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return read(fd, buf, count);
}

int
secwrite(int fd, void *buf, size_t count)
{
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, count);
	else
#endif		/* HANDLE_SSL */
		return write(fd, buf, count);
}

int
secfwrite(void *buf, size_t size, size_t count, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, size), count;
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
	if (config.usessl)
		return SSL_write(ssl, buf, strlen(buf));
	else
#endif		/* HANDLE_SSL */
		return printf("%s", buf);
}

int
secfputs(char *buf, FILE *stream)
{
#ifdef		HANDLE_SSL
	if (config.usessl)
		return SSL_write(ssl, buf, strlen(buf));
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


