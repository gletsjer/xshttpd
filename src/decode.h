/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#ifndef		DECODE_H
#define		DECODE_H

#include	"config.h"
#include	<stdbool.h>

bool	decode		(char * const) NONNULL;
void	uudecode	(char * const) NONNULL;
char	*escape		(const char * const) MALLOC_FUNC NONNULL;
char	*urlencode	(const char * const, bool) MALLOC_FUNC NONNULL;
char	*shellencode	(const char * const) MALLOC_FUNC NONNULL;
int	hexdigit	(char) CONST_FUNC NONNULL;
void	hex_encode	(const char * const bin, size_t len, char *hex) NONNULL;
void	hex_decode	(const char * const hex, size_t len, char *bin) NONNULL;
int	base64_encode	(const char * const msg, size_t len, char *bin) NONNULL;

#endif		/* DECODE_H */
