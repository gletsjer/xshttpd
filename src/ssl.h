#include	"config.h"

/* Wrapper functions are used even if SSL is not enabled */
int	initssl(int);
void	loadssl(void);
void	endssl(int);
void	setreadmode(int, int);
int	secread(int, void *, size_t);
int	secwrite(int, void *, size_t);
int	secfwrite(void *, size_t, size_t, FILE *);
int	secprintf(const char *format, ...) PRINTF_LIKE(1, 2);
int	secfputs(char *, FILE *);

