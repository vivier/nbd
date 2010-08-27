#include "config.h"
#include "libnbd.h"

int nbd_client_clear(int nbd)
{
	if (ioctl(nbd, NBD_CLEAR_QUE) < 0)
		return -errno;

	if (ioctl(nbd, NBD_CLEAR_SOCK) < 0)
		return -errno;

	return 0;
}
