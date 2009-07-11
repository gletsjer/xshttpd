
#ifndef		HTTYPES_H
#define		HTTYPES_H

typedef	enum { log_none, log_traditional, log_combined, log_virtual }	logstyle_t;
typedef enum { auth_none, auth_optional, auth_strict }	sslauth_t;
typedef enum { ERR_NONE, ERR_CONT, ERR_QUIT, ERR_LINE, ERR_CLOSE } xs_error_t;
typedef enum { rh_dflt = 0, rh_lastmod = 1, rh_texthtml = 2 } xs_rhflags_t;
typedef enum { redir_dflt = 0, redir_perm = 1, redir_env = 2 } xs_redirflags_t;

struct mapping
{
	char	*index, *value;
};
struct maplist
{
	size_t		size;
	struct mapping	*elements;
};

#endif		/* HTTYPES_H */
