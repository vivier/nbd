#include "config.h"

#include <sys/mount.h>

#include "libnbd.h"

int nbd_client_setsizes(int nbd, u64 size64, int blocksize, u32 flags) {
	unsigned long size;
	int read_only = (flags & NBD_FLAG_READ_ONLY) ? 1 : 0;

#ifdef NBD_SET_SIZE_BLOCKS
	if (size64/blocksize > (~0UL >> 1))
		return -EFBIG;
	else {
		int er;
		if (ioctl(nbd, NBD_SET_BLKSIZE, (unsigned long)blocksize) < 0)
			return -errno;
		size = (unsigned long)(size64/blocksize);
		if ((er = ioctl(nbd, NBD_SET_SIZE_BLOCKS, size)) < 0)
			return -errno;
	}
#else
	if (size64 > (~0UL >> 1)) {
		return -EFBIG;
	} else {
		size = (unsigned long)size64;
		if (ioctl(nbd, NBD_SET_SIZE, size) < 0)
			return -errno;
	}
#endif

	ioctl(nbd, NBD_CLEAR_SOCK);

	if (ioctl(nbd, BLKROSET, (unsigned long) &read_only) < 0)
		return -errno;

	return 0;
}
