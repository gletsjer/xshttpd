#include	"config.h"
#include	<sys/socket.h>
#include	<arpa/inet.h>

int
inet_aton(const char *cp, struct in_addr *ia)
{
#ifdef		HAVE_INET_PTON
	return inet_pton(AF_INET, cp, ia);
#else		/* HAVE_INET_PTON */
	*ia = inet_addr(cp);
	/* return 1 on success */
	return *ia != INADDR_NONE;
#endif		/* HAVE_INET_PTON */
}
