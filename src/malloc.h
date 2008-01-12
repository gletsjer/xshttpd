#ifndef		MALLOC_H
#define		MALLOC_H

#include	"htconfig.h"
#include	<stdlib.h>
#include	<err.h>

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

#endif		/* MALLOC_H */
