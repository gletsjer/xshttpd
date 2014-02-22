#ifndef		MALLOC_H
#define		MALLOC_H

#include	<stdlib.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */

#include	"alternative.h"

#define		MALLOC(var,type,num)					\
		do							\
		{							\
			(var) = (type *)malloc((num) * sizeof(type));	\
			if (!(var))					\
			{						\
				err(1, "malloc for %s failed", #var);	\
				/* NOTREACHED */			\
			}						\
		} while (0)

#define		CALLOC(var,type,num)					\
		do							\
		{							\
			(var) = (type *)calloc((num), sizeof(type));	\
			if (!(var))					\
			{						\
				err(1, "calloc for %s failed", #var);	\
				/* NOTREACHED */			\
			}						\
		} while (0)

#define		REALLOC(var,type,num)					\
		do							\
		{							\
			type *_var = (type *)				\
				realloc((var), (num) * sizeof(type));	\
			if (!_var)					\
			{						\
				err(1, "realloc for %s failed", #var);	\
				/* NOTREACHED */			\
			}						\
			var = _var;					\
		} while (0)

#define		STRDUP(dst,str)						\
		do							\
		{							\
			const char *_var = (str);			\
			char *_dst = NULL;				\
			if (_var)					\
			{						\
				_dst = strdup(_var);			\
				if (!_dst)				\
				{					\
					err(1, "strdup for %s failed", #dst);\
					/* NOTREACHED */		\
				}					\
			}						\
			(dst) = _dst;					\
		} while (0)

#define		STRNDUP(dst,str,sz)					\
		do							\
		{							\
			const char *_var = (str);			\
			char *_dst = NULL;				\
			if (_var)					\
			{						\
				_dst = strndup(_var, (sz));		\
				if (!_dst)				\
				{					\
					err(1, "strndup for %s failed", #dst);\
					/* NOTREACHED */		\
				}					\
			}						\
			(dst) = _dst;					\
		} while (0)

#define		FREE(var)						\
		do							\
		{							\
			if (var)					\
			{						\
				free(var);				\
				var = NULL;				\
			}						\
		} while(0)

#define		NOTNULL(var)						\
		do							\
		{							\
			if (!(var))					\
			{						\
				err(1, "memory allocation failed");	\
				/* NOTREACHED */			\
			}						\
		} while(0)

#define		ASPRINTF(str,fmt,...)					\
		do							\
		{							\
			if (asprintf(str, fmt, __VA_ARGS__) < 0)	\
			{						\
				err(1, "asprintf for %s failed", #str);	\
				/* NOTREACHED */			\
			}						\
		} while(0)

#define		ASPRINTFVAL(num,str,fmt,...)				\
		do							\
		{							\
			int _num = asprintf(str, fmt, __VA_ARGS__);	\
			if (_num < 0)					\
			{						\
				err(1, "asprintf for %s failed", #str);	\
				/* NOTREACHED */			\
			}						\
			(num) = _num;					\
		} while(0)

#define		VASPRINTF(str,fmt,ap)					\
		do							\
		{							\
			if (vasprintf(str, fmt, ap) < 0)		\
			{						\
				err(1, "vasprintf for %s failed", #str);\
				/* NOTREACHED */			\
			}						\
		} while(0)

#define		VASPRINTFVAL(num,str,fmt,ap)				\
		do							\
		{							\
			int _num = vasprintf(str, fmt, ap);		\
			if (_num < 0)					\
			{						\
				err(1, "vasprintf for %s failed", #str);\
				/* NOTREACHED */			\
			}						\
			(num) = _num;					\
		} while(0)

#endif		/* MALLOC_H */
