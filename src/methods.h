/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */

#ifndef		METHODS_H
#define		METHODS_H

void	loadcompresstypes	(void);
void	loadscripttypes		(char *, char *);
void	loadfiletypes		(char *, char *);

void	do_get			(char *);
void	do_post			(char *);
void	do_head			(char *);
void	do_options		(const char *);
void	do_trace		(const char *);
void	do_proxy		(const char *, const char *);

#endif		/* METHODS_H */
