
#ifndef		HTTYPES_H
#define		HTTYPES_H

typedef	enum { log_none, log_traditional, log_combined, log_virtual }	logstyle_t;
typedef enum { auth_none, auth_optional, auth_strict }	sslauth_t;
typedef enum { ERR_NONE, ERR_CONT, ERR_QUIT, ERR_LINE, ERR_CLOSE } xs_error_t;

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
