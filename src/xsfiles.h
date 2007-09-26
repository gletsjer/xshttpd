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
} cf_values;

int	check_file_redirect	(const char *, const char *);
int	check_redirect		(const char *, const char *);
int	check_allow_host	(const char *, char *);
int	check_noxs		(const char *);
int	check_location		(const char *, const char *);
int	check_xsconf		(const char *, const char *, cf_values *);
int	free_xsconf		(cf_values *);

#endif		/* XSFILES_H */
