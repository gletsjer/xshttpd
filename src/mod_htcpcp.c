/* Copyright (C) 2009 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<unistd.h>

#include	"httypes.h"
#include	"malloc.h"
#include	"modules.h"
#include	"constants.h"
#include	"extra.h"

bool	htcpcp	(struct maplist *qh, 
		read_callback_t rcb, write_callback_t wcb);
bool	htcpcp_config(const char *, const char *);
bool	htcpcp_open	(void);

bool
htcpcp(struct maplist *qh, read_callback_t rcb, write_callback_t wcb)
{
	const char	err_msg[] = "It's a webserver Jim, not a coffeepot!";
	const char	body_msg[] = "I'm a teapot with an identity crisis.";
	const int	O = append_ifempty;
	char		*msg,
			timestamp[80];
	int		msglen;
	time_t		now;

	if (qh->size &&
		!strcasecmp(qh->elements[0].index, "Status") &&
		strcasestr(qh->elements[0].value, " HTCPCP/"))
		/* Bingo */;
	else
		return false;

	time(&now);
	strftime(timestamp, sizeof(timestamp),
		"%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));

	msglen = asprintf(&msg, "HTCPCP/1.0 418 %s\r\n"
		"Date: %s\r\n"
		"Server: %s\r\n"
		"Content-type: text/plain\r\n"
		"Content-length: %zd\r\n"
		"\r\n"
		"%s\r\n",
		err_msg,
		timestamp,
		SERVER_IDENT,
		sizeof(body_msg), body_msg);

	if (msglen < 0)
		return false;

	wcb(msg, msglen);
	FREE(msg);

	return true;
}

struct module htcpcp_module =
{
	.name = "hyper text coffee pot control protocol",
	.protocol_handler = htcpcp,
};

