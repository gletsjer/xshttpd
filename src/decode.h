/* Copyright (C) 2005 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

int	decode			(char *);
void	uudecode		(char *);
char	*escape			(const char *) MALLOC;
int	hexdigit		(int) CONST_FUNC;
int	hex_encode	(const char *bin, size_t len, char *hex);
int	hex_decode	(const char *hex, size_t len, char *bin);
int	generate_ha1	(const char *user, const char *passwd, char *hash);

