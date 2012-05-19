/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		METHODS_H
#define		METHODS_H

#include	"config.h"

void	loadcompresstypes	(void);
void	loadscripttypes		(const char * const, const char * const);
void	loadfiletypes		(const char * const, const char * const);

void	do_get			(char *);
void	do_post			(char *);
void	do_head			(char *);
void	do_put			(char *);
void	do_delete		(char *);
void	do_options		(const char * const);
void	do_trace		(const char * const);
void	do_proxy		(const char * const, const char * const);

bool	writeheaders		(void);

#endif		/* METHODS_H */
