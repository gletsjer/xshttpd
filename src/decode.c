/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* $Id: decode.c,v 1.6 2006/05/01 19:45:38 johans Exp $ */

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	<ctype.h>
#include	"config.h"
#include	"httpd.h"
#include	"decode.h"

/* Static arrays */

static	char	six2pr[64] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

int
decode(char *str)
{
	char		*posd, chr;
	const	char	*poss;
	unsigned int	top, bottom;

	poss = posd = str;
	while ((chr = *poss))
	{
		if (chr != '%')
		{
			if (chr == '?')
			{
				memmove(posd, poss, strlen(poss) + 1);
				return(ERR_NONE);
			}
			*(posd++) = chr;
			poss++;
		} else
		{
			if (hexdigit((int)poss[1]) < 0 ||
				hexdigit((int)poss[2]) < 0)
			{
				return(ERR_QUIT);
			}
			top = hexdigit((int)poss[1]);
			bottom = hexdigit((int)poss[2]);
			*(posd++) = (top << 4) + bottom;
			poss += 3;
		}
	}
	*posd = 0;
	return(ERR_NONE);
}

void
uudecode(char *buffer)
{
	unsigned char	pr2six[256], bufplain[32], *bufout = bufplain;
	int		nbytesdecoded, j, nprbytes;
	char		*bufin = buffer;

	for (j = 0; j < 256; j++)
		pr2six[j] = 64;
	for (j = 0; j < 64; j++)
		pr2six[(int)six2pr[j]] = (unsigned char)j;
	bufin = buffer;
	while (pr2six[(int)*(bufin++)] <= 63)
		/* NOTHING HERE */;
	nprbytes = (bufin - buffer) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;
	bufin = buffer;
	while (nprbytes > 0)
	{
		*(bufout++) = (unsigned char) ((pr2six[(int)*bufin] << 2) |
			(pr2six[(int)bufin[1]] >> 4));
		*(bufout++) = (unsigned char) ((pr2six[(int)bufin[1]] << 4) |
			(pr2six[(int)bufin[2]] >> 2));
		*(bufout++) = (unsigned char) ((pr2six[(int)bufin[2]] << 6) |
			(pr2six[(int)bufin[3]]));
		bufin += 4; nprbytes -= 4;
	}

	if (nprbytes & 3)
	{
		if (pr2six[(int)*(bufin - 2)] > 63)
			nbytesdecoded -= 2;
		else
			nbytesdecoded--;
	}
	if (nbytesdecoded)
		memmove(buffer, (char *)bufplain, nbytesdecoded);
	buffer[nbytesdecoded] = 0;
}

char	*
escape(const char *what)
{
	size_t		len;
	const char	*p;
	char		*buffer = malloc(BUFSIZ);

	if (!buffer)
		return NULL;

	buffer[0] = '\0';
	for (p = what; (len = strcspn(p, "<>&\"")); p += len + 1)
	{
		if (strlen(buffer) + len < BUFSIZ)
			strncat(buffer, p, len);
		if (!p[len])
			break;
		switch (p[len])
		{
		case '<':
			strlcat(buffer, "&lt;", BUFSIZ);
			break;
		case '>':
			strlcat(buffer, "&gt;", BUFSIZ);
			break;
		case '&':
			strlcat(buffer, "&amp;", BUFSIZ);
			break;
		case '"':
			strlcat(buffer, "&quot;", BUFSIZ);
			break;
		default:
			/* do nothing */;
		}
	}
	return (buffer);
}


int
hexdigit(int ch)
{
	const	char	*temp, *hexdigits = "0123456789ABCDEF";

	if ((temp = strchr(hexdigits, islower(ch) ? toupper(ch) : ch)))
		return (temp - hexdigits);
	else
	{
		return (-1);
	}
}


