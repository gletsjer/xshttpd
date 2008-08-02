/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		DECODE_H
#define		DECODE_H

#include	"config.h"
#include	<stdbool.h>

bool	decode		(char *) NONNULL;
void	uudecode	(char *) NONNULL;
char	*escape		(const char *) MALLOC_FUNC NONNULL;
char	*urlencode	(const char *, bool) MALLOC_FUNC NONNULL;
char	*shellencode	(const char *) MALLOC_FUNC NONNULL;
int	hexdigit	(char) CONST_FUNC NONNULL;
void	hex_encode	(const char *bin, size_t len, char *hex) NONNULL;
void	hex_decode	(const char *hex, size_t len, char *bin) NONNULL;
int	base64_encode	(const char *msg, size_t len, char *bin) NONNULL;

void	generate_ha1	(const char *user, const char *passwd, char *hash) NONNULL;

#endif		/* DECODE_H */
