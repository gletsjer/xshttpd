/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		DECODE_H
#define		DECODE_H

#include	"config.h"

int	decode			(char *);
void	uudecode		(char *);
char	*escape			(const char *) MALLOC_FUNC;
char	*urlencode		(const char *) MALLOC_FUNC;
char	*shellencode		(const char *) MALLOC_FUNC;
int	hexdigit		(int) CONST_FUNC;
int	hex_encode	(const char *bin, size_t len, char *hex);
int	hex_decode	(const char *hex, size_t len, char *bin);
int base64_encode(const char *msg, size_t len, char *bin);

int	generate_ha1	(const char *user, const char *passwd, char *hash);

#endif		/* DECODE_H */
