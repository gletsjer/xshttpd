#include	"config.h"
#include	<stdio.h>

/* Wrapper functions are used even if SSL is not enabled */
int	initssl(void);
void	loadssl(void);
void	endssl(void);
void	setreadmode(int, int);
ssize_t	secread(int, void *, size_t);
size_t	secfread(void *, size_t, size_t, FILE *);
ssize_t	secwrite(const char *, size_t);
size_t	secfwrite(const char *, size_t, size_t, FILE *);
ssize_t	secputs(const char *);
ssize_t	secprintf(const char *format, ...) PRINTF_LIKE(1, 2);

