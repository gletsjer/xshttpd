#include	"config.h"

#ifdef		HANDLE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
extern	SSL_CTX *ssl_ctx;
#endif		/* HANDLE_SSL */

/* Wrapper functions are used even if SSL is not enabled */
int	initssl(int);
void	loadssl(void);
void	endssl(int);
void	setreadmode(int, int);
int	secread(int, void *, size_t);
int	secwrite(int, void *, size_t);
int	secfwrite(void *, size_t, size_t, FILE *);
int	secprintf(const char *format, ...);
int	secfputs(char *, FILE *);

