#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "libnbd.h"

int nbd_client_disconnect(char* device) {
	int nbd = open(device, O_RDWR);
	if (nbd < 0)
		return -errno;
	if (ioctl(nbd, NBD_CLEAR_QUE)< 0)
		return -errno;

#ifdef NBD_DISCONNECT
	if (ioctl(nbd, NBD_DISCONNECT)<0)
		return -errno;
#else
	return -ENOSYS;
#endif
	if (ioctl(nbd, NBD_CLEAR_SOCK)<0)
		return -errno;
	return 0;
}
