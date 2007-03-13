/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2006 by Johan van Selst (johans@stack.nl) */
/* $Id: decode.c,v 1.9 2007/03/13 13:30:57 johans Exp $ */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	<ctype.h>

#include	"httpd.h"
#include	"decode.h"
#include	"authenticate.h"
#include	"md5.h"

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

/* sizeof(hex) >= 2 * len + 1 */
int
hex_encode(const char *bin, size_t len, char *hex)
{
	unsigned short	i;
	unsigned char	j;

	for (i = 0; i < len; i++)
	{
		j = (bin[i] >> 4) & 0xf;
		if (j <= 9)
			hex[i * 2] = (j + '0');
		else
			hex[i * 2] = (j + 'a' - 10);
		j = bin[i] & 0xf;
		if (j <= 9)
			hex[i * 2 + 1] = (j + '0');
		else
			hex[i * 2 + 1] = (j + 'a' - 10);
	}
	hex[2 * len] = '\0';
	return 0;
}

/* sizeof(bin) >= len / 2 */
int
hex_decode(const char *hex, size_t len, char *bin)
{
	unsigned short i;
	char j;

	for (i = 0; i < len; i += 2)
	{
		j = hex[i];
		if (j <= '9')
			bin[i / 2] = (j - '0') << 4;
		else
			bin[i / 2] = (j - 'a') << 4;
		j = hex[i + 1];
		if (j <= '9')
			bin[i / 2] |= (j - '0');
		else
			bin[i / 2] |= (j - 'a');
	}
	return 0;
}

#ifdef		HAVE_MD5
/* sizeof(hash) >= MD5_DIGEST_STRING_LENGTH */
int
generate_ha1(const char *user, const char *passwd, char *ha1)
{
	char	*a1;
	size_t	len;

	/* calculate h(a1) */
	len = asprintf(&a1, "%s:%s:%s", user, REALM, passwd);
	MD5Data((const unsigned char *)a1, len, ha1);
	free(a1);

	return 0;
}
#endif		/* HAVE_MD5 */


