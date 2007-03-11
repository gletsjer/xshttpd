/* Copyright (C) 2007 by Johan van Selst (johans@stack.nl) */

#define		REALM		"this page"
#define		MAX_NONCE_LENGTH	60

extern char	authentication[MYBUFSIZ];

void	initnonce	(void);
int	check_auth	(FILE *);
int	generate_ha1	(const char *user, const char *passwd, char *hash);

