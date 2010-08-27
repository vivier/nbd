#include <stdio.h>

#include "config.h"
#include "libnbd.h"

int nbd_client_set_timeout(int nbd, int timeout) {
	if (timeout) {
#ifdef NBD_SET_TIMEOUT
		if (ioctl(nbd, NBD_SET_TIMEOUT, (unsigned long)timeout) < 0)
			return -errno;
#else
		return -ENOSYS;
#endif
	}
	return 0;
}
