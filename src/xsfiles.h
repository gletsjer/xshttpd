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
	char	*csp;
	char	*putscript;
	char	*delscript;
	bool	noprivs;
} cf_values;

bool	check_file_redirect	(const char * const, const char * const) WARNUNUSED;
bool	check_redirect		(const char * const, const char * const) WARNUNUSED;
bool	check_allow_host	(const char * const, char * const) WARNUNUSED;
bool	check_noxs		(const char * const) WARNUNUSED;
bool	check_location		(const char * const, const char * const) WARNUNUSED;
bool	check_xsconf		(const char * const, const char * const, const int, cf_values * const) WARNUNUSED;
void	free_xsconf		(cf_values *) NONNULL;

#endif		/* XSFILES_H */
