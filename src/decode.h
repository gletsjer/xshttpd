/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		DECODE_H
#define		DECODE_H

#include	"config.h"

int	decode		(char *) NONNULL;
void	uudecode	(char *) NONNULL;
char	*escape		(const char *) MALLOC_FUNC NONNULL;
char	*urlencode	(const char *) MALLOC_FUNC NONNULL;
char	*shellencode	(const char *) MALLOC_FUNC NONNULL;
int	hexdigit	(int) CONST_FUNC NONNULL;
int	hex_encode	(const char *bin, size_t len, char *hex) NONNULL;
int	hex_decode	(const char *hex, size_t len, char *bin) NONNULL;
int	base64_encode	(const char *msg, size_t len, char *bin) NONNULL;

int	generate_ha1	(const char *user, const char *passwd, char *hash) NONNULL;

#endif		/* DECODE_H */
