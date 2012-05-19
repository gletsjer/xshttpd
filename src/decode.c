/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2010 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<unistd.h>

#include	"htconfig.h"
#include	"httpd.h"
#include	"decode.h"
#include	"authenticate.h"
#include	"malloc.h"
#include	"hash.h"

/* Static arrays */

static	const char	six2pr[64] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

bool
decode(char * const str)
{
	char		*posd, chr;
	const	char	*poss;

	poss = posd = str;
	while ((chr = *poss))
	{
		if (chr != '%')
		{
			if (chr == '?')
			{
				memmove(posd, poss, strlen(poss) + 1);
				return true;
			}
			*(posd++) = chr;
			poss++;
		}
		else
		{
			const int	top = hexdigit(poss[1]);
			const int	bottom = hexdigit(poss[2]);

			if (top < 0 || bottom < 0)
				return false;
			*(posd++) = (top << 4) + bottom;
			poss += 3;
		}
	}
	*posd = 0;
	return true;
}

void
uudecode(char * const buffer)
{
	unsigned char	pr2six[256], bufplain[32], *bufout = bufplain;
	unsigned int	nbytesdecoded;
	int		nprbytes;
	char		*bufin = buffer;

	for (int j = 0; j < 256; j++)
		pr2six[j] = 64;
	for (int j = 0; j < 64; j++)
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
		bufin += 4;
		nprbytes -= 4;
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
escape(const char * const what)
{
	size_t		len, sz;
	const char	*p;
	char		*buffer;

	if (!what || !*what)
		return NULL;

	sz = strlen(what) + 1;
	for (p = what; p[len = strcspn(p, "<>&\"")]; p += len + 1)
		sz += 10;

	MALLOC(buffer, char, sz);

	buffer[0] = '\0';
	for (p = what; p[len = strcspn(p, "<>&\"")]; p += len + 1)
	{
		strncat(buffer, p, len);
		switch (p[len])
		{
		case '<':
			strcat(buffer, "&lt;");
			break;
		case '>':
			strcat(buffer, "&gt;");
			break;
		case '&':
			strcat(buffer, "&amp;");
			break;
		case '"':
			strcat(buffer, "&quot;");
			break;
		default:
			/* do nothing */;
		}
	}
	strncat(buffer, p, len);
	return buffer;
}

char	*
urlencode(const char * const what, bool delimenc)
{
	const char	*p;
	char		*q, *buffer;

	if (!what)
		return NULL;

	MALLOC(buffer, char, strlen(what) * 3 + 1);
	q = buffer;
	/* don't urlencode host-info */
	if ((p = strstr(what, "://")) && !delimenc)
	{
		bool		hashost = isalpha(what[0]);
		const char	*s;

		for (s = what + 1; s < p; s++)
			hashost &= isalnum(*s) ||
				'+' == *s || '-' == *s || '.' == *s;
		if (hashost)
		{
			if ((p = strchr(p + 3, '/')))
				p++;
			else
				p = strchr(p, '\0');
			strlcpy(buffer, what, p - what + 1);
			q = strchr(buffer, '\0');
		}
		else
			p = NULL;
	}

	/* start encoding past host-info (if any) */
	/* DECL */
	const char	mark[] =
		{ '-', '_', '.', '!', '~', '*', '\'', '(', ')' };
	const char	delim[] =
		{ ';', '/', '?', '@', '&', '=', '+', '$', ',' };
	for (p = p ? p : what; *p; p++)
		if (' ' == *p)
			*q++ = '+';
		else if (isalnum(*p) || strchr(mark, *p))
			*q++ = *p;
		else if (!delimenc && strchr(delim, *p))
			*q++ = *p;
		else
			q += sprintf(q, "%%%02hhx", (unsigned char)*p);
	*q++ = '\0';
	REALLOC(buffer, char, q - buffer);
	return buffer;
}

char	*
shellencode(const char * const what)
{
	char		*q, *buffer;

	MALLOC(buffer, char, strlen(what) * 2 + 1);
	q = buffer;
	for (const char *p = what; *p; p++)
		if (!strchr("&;`'|*?-~<>^()[]{}$\\", *p))
			*q++ = *p;
		else
		{
			*q++ = '\\';
			*q++ = *p;
		}
	*q++ = '\0';
	REALLOC(buffer, char, q - buffer);
	return buffer;
}

int
hexdigit(char ch)
{
	const	char	*temp;
	const	char	hexdigits[] = "0123456789ABCDEF";
	const	int	ich = ch;

	if ((temp = strchr(hexdigits, islower(ich) ? toupper(ich) : ich)))
		return (temp - hexdigits);
	else
		return (-1);
}

/* sizeof(hex) >= 2 * len + 1 */
void
hex_encode(const char * const bin, size_t len, char * const hex)
{
	for (size_t i = 0; i < len; i++)
	{
		unsigned char j = (bin[i] >> 4) & 0xf;

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
}

/* sizeof(bin) >= len / 2 */
void
hex_decode(const char * const hex, size_t len, char * const bin)
{
	for (size_t i = 0; i < len; i += 2)
	{
		char j = hex[i];

		if (j <= '9')
			bin[i / 2] = (j - '0') << 4;
		else
			bin[i / 2] = (j - 'a' + 10) << 4;
		j = hex[i + 1];
		if (j <= '9')
			bin[i / 2] |= (j - '0');
		else
			bin[i / 2] |= (j - 'a' + 10);
	}
}

/* sizeof(bin) >= (len * 4 + 2) / 3 + 1 */
int
base64_encode(const char * const input, size_t len, char * const bin)
{
	int		bits;
	const char	*msg = input;
	char		*d;

	/* 3 bytes becomes 4 chars, but round up and allow for trailing NUL */
	d = bin;

	/* Convert each group of 3 bytes into 4 characters. */
	while (len >= 3)
	{
		bits = (((int)msg[0] << 16) & 0xff0000)
			| (((int)msg[1] << 8) & 0xff00)
			| (((int)msg[2]) & 0x00ff);
		msg += 3;
		len -= 3;
		*d++ = six2pr[(bits >> 18) & 0x3f];
		*d++ = six2pr[(bits >> 12) & 0x3f];
		*d++ = six2pr[(bits >> 6) & 0x3f];
		*d++ = six2pr[(bits) & 0x3f];
	}
	/* Handle final group of 1 byte (2 chars) or 2 bytes (3 chars). */
	switch (len)
	{
	case 0:
		break;
	case 1:
		bits = (((int)msg[0] << 16) & 0xff0000);
		*d++ = six2pr[(bits >> 18) & 0x3f];
		*d++ = six2pr[(bits >> 12) & 0x3f];
		*d++ = '=';
		*d++ = '=';
		break;
	case 2:
		bits = (((int)msg[0] << 16) & 0xff0000)
			| (((int)msg[1] << 8) & 0xff00);
		*d++ = six2pr[(bits >> 18) & 0x3f];
		*d++ = six2pr[(bits >> 12) & 0x3f];
		*d++ = six2pr[(bits >> 6) & 0x3f];
		*d++ = '=';
		break;
	}
	/* Add trailing NUL character so output is a valid C string. */
	*d++ = '\0';
	return (d - bin);
}

