#include "config.h"

#include <sys/mman.h>
#include "libnbd.h"

int nbd_client_finish_sock(int sock, int nbd, int swap) {
	if (ioctl(nbd, NBD_SET_SOCK, sock) < 0)
		return -errno;

	if (swap)
		mlockall(MCL_CURRENT | MCL_FUTURE);
	return 0;
}
