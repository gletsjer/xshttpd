/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

/* $Id: decode.c,v 1.1 2005/01/17 20:41:19 johans Exp $ */

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	<ctype.h>
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
	int		top, bottom;

	poss = posd = str;
	while ((chr = *poss))
	{
		if (chr != '%')
		{
			if (chr == '?')
			{
				bcopy(poss, posd, strlen(poss) + 1);
				return(ERR_NONE);
			}
			*(posd++) = chr;
			poss++;
		} else
		{
			if ((top = hexdigit((int)poss[1])) < 0)
				return(ERR_QUIT);
			if ((bottom = hexdigit((int)poss[2])) < 0)
				return(ERR_QUIT);
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
		bcopy((char *)bufplain, buffer, nbytesdecoded);
	buffer[nbytesdecoded] = 0;
}

char	*
escape(const char *what)
{
	char		*escapebuf, *w;

	if (!(w = escapebuf = (char *)malloc(BUFSIZ)))
		return(NULL);
	while (*what && ((w - escapebuf) < (BUFSIZ - 10)))
	{
		switch(*what)
		{
		case '<':
			strcpy(w, "&lt;"); w += 4;
			break;
		case '>':
			strcpy(w, "&gt;"); w += 4;
			break;
		case '&':
			strcpy(w, "&amp;"); w += 5;
			break;
		case '"':
			strcpy(w, "&quot;"); w += 6;
			break;
		default:
			*(w++) = *what;
			break;
		}
		what++;
	}
	*w = 0;
	return(escapebuf);
}

int
hexdigit(int ch)
{
	const	char	*temp, *hexdigits = "0123456789ABCDEF";

	if ((temp = strchr(hexdigits, islower(ch) ? toupper(ch) : ch)))
		return (temp - hexdigits);
	else
	{
		error("500 Invalid `percent' parameters");
		return (-1);
	}
}


