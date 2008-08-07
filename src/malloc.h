#ifndef		MALLOC_H
#define		MALLOC_H

#include	<stdlib.h>
#ifdef		HAVE_ERR_H
#include	<err.h>
#endif		/* HAVE_ERR_H */

#include	"htconfig.h"
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

#endif		/* MALLOC_H */
