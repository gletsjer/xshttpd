#ifndef		XSFILES_H
#define		XSFILES_H

typedef struct cf_values
{
	char	*charset;
	char	*mimetype;
	char	*scripttype;
	char	*language;
	char	*encoding;
	char	*indexfile;
	char	*p3pref;
	char	*p3pcp;
	char	*putscript;
	char	*delscript;
} cf_values;

int	check_file_redirect	(const char *, const char *) WARNUNUSED;
int	check_redirect		(const char *, const char *) WARNUNUSED;
int	check_allow_host	(const char *, char *) WARNUNUSED;
int	check_noxs		(const char *) WARNUNUSED;
int	check_location		(const char *, const char *) WARNUNUSED;
int	check_xsconf		(const char *, const char *, cf_values *) WARNUNUSED;
int	free_xsconf		(cf_values *) NONNULL;

#endif		/* XSFILES_H */
